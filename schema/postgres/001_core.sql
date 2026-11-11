-- =============================================================================
-- DMF (Document Management Framework) core schema — PostgreSQL 16+
--
-- PROV-DM mapping (see docs/ARCHITECTURE.md §1):
--   prov:Entity   -> document, document_version, module_revision, content_blob,
--                    decision, verification_run, release, policy (prov:Plan)
--   prov:Activity -> activity (typed), ticket (a prov:Activity that bundles sub-activities)
--   prov:Agent    -> agent (Person / SoftwareAgent / Organization)
--   relations     -> activity.ticket_id (dct:isPartOf), association, usage,
--                    *.generated_by (wasGeneratedBy), *.derived_from (wasDerivedFrom)
--
-- Invariants enforced here (defense in depth; the service enforces them first):
--   I-1 Entities are immutable once written (forbid_mutation trigger).
--   I-2 Document head moves only by compare-and-swap on change_token (advance_head).
--   I-3 restrict_seal can only change via an APPROVED CORE_AMENDMENT ticket.
--   I-4 Audit log is append-only and each row links to its predecessor's hash.
--   I-5 Tenant isolation via row-level security on every tenant-owned table.
-- =============================================================================

CREATE SCHEMA IF NOT EXISTS dmf;
SET search_path = dmf, public;

-- ---------------------------------------------------------------- enums
CREATE TYPE agent_kind        AS ENUM ('PERSON', 'SOFTWARE', 'ORGANIZATION');
CREATE TYPE mutability        AS ENUM ('MUTABLE', 'RESTRICTED', 'IMMUTABLE_CORE');
CREATE TYPE ticket_kind       AS ENUM ('EDIT', 'DECOMPOSE', 'MERGE', 'CONFLICT_RESOLUTION',
                                       'ROLLBACK', 'CORE_AMENDMENT', 'PROMOTION', 'POLICY_CHANGE');
CREATE TYPE ticket_status     AS ENUM ('DRAFT', 'OPEN', 'IN_PROGRESS', 'RESTRICT_CHECK', 'VERIFYING',
                                       'PENDING_APPROVAL', 'APPROVED', 'SHADOW', 'PROMOTED', 'CLOSED',
                                       'REJECTED', 'CANCELLED', 'ROLLED_BACK');
CREATE TYPE activity_type     AS ENUM ('CREATE', 'EDIT', 'DECOMPOSE', 'MERGE', 'RESTRICT_CHECK',
                                       'VERIFY', 'APPROVE', 'SHADOW_DEPLOY', 'PROMOTE', 'ROLLBACK');
CREATE TYPE policy_kind       AS ENUM ('APPROVAL', 'RESTRICT', 'GATE', 'ACCEPTANCE', 'ACCESS');
CREATE TYPE decision_outcome  AS ENUM ('APPROVE', 'REJECT', 'REQUEST_CHANGES');
CREATE TYPE check_outcome     AS ENUM ('PASS', 'FAIL', 'ERROR', 'NEEDS_HUMAN', 'SKIPPED');
CREATE TYPE release_channel   AS ENUM ('SHADOW', 'OFFICIAL');
CREATE TYPE release_status    AS ENUM ('ACTIVE', 'SUPERSEDED', 'REVOKED');

-- ---------------------------------------------------------------- helpers
CREATE OR REPLACE FUNCTION forbid_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'DMF-I1: % on immutable table %.% is forbidden', TG_OP, TG_TABLE_SCHEMA, TG_TABLE_NAME
    USING ERRCODE = 'P0001';
END $$;

CREATE OR REPLACE FUNCTION current_tenant() RETURNS uuid LANGUAGE sql STABLE AS $$
  SELECT current_setting('dmf.tenant_id')::uuid
$$;

-- ---------------------------------------------------------------- agents (prov:Agent)
CREATE TABLE tenant (
  id          uuid PRIMARY KEY,
  name        text NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE agent (
  id                  uuid PRIMARY KEY,
  tenant_id           uuid NOT NULL REFERENCES tenant(id),
  kind                agent_kind NOT NULL,
  iri                 text NOT NULL UNIQUE,              -- urn:dmf:agent:<id>
  display_name        text NOT NULL,
  acted_on_behalf_of  uuid REFERENCES agent(id),         -- prov:actedOnBehalfOf (bots, delegation)
  attributes          jsonb NOT NULL DEFAULT '{}',       -- ABAC: dept, clearance, roles...
  created_at          timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------- policies (prov:Plan)
CREATE TABLE policy (
  id            uuid PRIMARY KEY,
  tenant_id     uuid NOT NULL REFERENCES tenant(id),
  kind          policy_kind NOT NULL,
  name          text NOT NULL,
  version       int  NOT NULL,
  body          jsonb NOT NULL,
  body_sha256   char(64) NOT NULL,                       -- sha256(JCS(body))
  effective_from timestamptz NOT NULL,
  generated_by  uuid,                                    -- POLICY_CHANGE activity
  created_at    timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, kind, name, version)
);
CREATE TRIGGER policy_immutable BEFORE UPDATE OR DELETE ON policy
  FOR EACH ROW EXECUTE FUNCTION forbid_mutation();

-- ---------------------------------------------------------------- content (CAS)
CREATE TABLE content_blob (
  sha256       char(64) PRIMARY KEY,                     -- content address (rule H-3)
  size_bytes   bigint NOT NULL,
  media_type   text NOT NULL,                            -- dc:format / cmis:contentStreamMimeType
  storage_uri  text NOT NULL,                            -- s3://dmf-cas/sha256/ab/cd/<hash>
  created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE TRIGGER content_blob_immutable BEFORE UPDATE OR DELETE ON content_blob
  FOR EACH ROW EXECUTE FUNCTION forbid_mutation();

-- ---------------------------------------------------------------- documents
-- cmis:document version series. Only mutable row type: head pointer + change token.
CREATE TABLE document (
  id                 uuid PRIMARY KEY,                   -- = cmis:versionSeriesId
  tenant_id          uuid NOT NULL REFERENCES tenant(id),
  iri                text NOT NULL UNIQUE,               -- urn:dmf:doc:<id>
  classification     text NOT NULL DEFAULT 'INTERNAL',   -- ABAC attribute
  owner_agent_id     uuid NOT NULL REFERENCES agent(id),
  dc                 jsonb NOT NULL DEFAULT '{}',        -- Dublin Core (title, subject, ...)
  head_version_id    uuid,                               -- cmis:isLatestVersion target
  change_token       bigint NOT NULL DEFAULT 0,          -- cmis:changeToken (OCC)
  created_at         timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE module (                                    -- logical identity of a section
  id          uuid PRIMARY KEY,
  tenant_id   uuid NOT NULL REFERENCES tenant(id),
  document_id uuid NOT NULL REFERENCES document(id),
  module_key  text NOT NULL,                             -- stable id e.g. 'sec.scope'
  kind        text NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  UNIQUE (document_id, module_key)
);

CREATE TABLE module_revision (                           -- prov:Entity, specializationOf module
  id               uuid PRIMARY KEY,
  tenant_id        uuid NOT NULL REFERENCES tenant(id),
  module_id        uuid NOT NULL REFERENCES module(id),
  content_sha256   char(64) NOT NULL REFERENCES content_blob(sha256),
  mutability       mutability NOT NULL,
  revision_of      uuid REFERENCES module_revision(id),  -- prov:wasRevisionOf
  generated_by     uuid NOT NULL,                        -- activity(id)
  created_at       timestamptz NOT NULL DEFAULT now()
);
CREATE TRIGGER module_revision_immutable BEFORE UPDATE OR DELETE ON module_revision
  FOR EACH ROW EXECUTE FUNCTION forbid_mutation();

CREATE TABLE document_version (                          -- prov:Entity + prov:Collection
  id                 uuid PRIMARY KEY,
  tenant_id          uuid NOT NULL REFERENCES tenant(id),
  document_id        uuid NOT NULL REFERENCES document(id),
  version_no         int  NOT NULL,
  version_label      text,                               -- cmis:versionLabel e.g. '2.1'
  parent_version_id  uuid REFERENCES document_version(id), -- prov:wasRevisionOf
  derived_from_id    uuid REFERENCES document_version(id), -- prov:wasDerivedFrom (rollback target)
  manifest_root      char(64) NOT NULL,                  -- rule H-4
  restrict_seal      char(64) NOT NULL,                  -- rule H-5
  version_hash       char(64) NOT NULL UNIQUE,           -- chain link
  parent_version_hash char(64),
  dc                 jsonb NOT NULL,                     -- frozen Dublin Core snapshot
  generated_by       uuid NOT NULL,                      -- activity(id)
  checkin_comment    text,                               -- cmis:checkinComment
  created_at         timestamptz NOT NULL DEFAULT now(),
  UNIQUE (document_id, version_no),
  CHECK ((parent_version_id IS NULL) = (parent_version_hash IS NULL))
);
CREATE TRIGGER document_version_immutable BEFORE UPDATE OR DELETE ON document_version
  FOR EACH ROW EXECUTE FUNCTION forbid_mutation();
ALTER TABLE document ADD CONSTRAINT document_head_fk
  FOREIGN KEY (head_version_id) REFERENCES document_version(id) DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE version_member (                            -- prov:hadMember / dct:hasPart
  version_id          uuid NOT NULL REFERENCES document_version(id),
  ordinal             int  NOT NULL,
  module_revision_id  uuid NOT NULL REFERENCES module_revision(id),
  depends_on          text[] NOT NULL DEFAULT '{}',      -- module_keys (dependency restriction)
  PRIMARY KEY (version_id, ordinal),
  UNIQUE (version_id, module_revision_id)
);
CREATE TRIGGER version_member_immutable BEFORE UPDATE OR DELETE ON version_member
  FOR EACH ROW EXECUTE FUNCTION forbid_mutation();

-- ---------------------------------------------------------------- tickets & activities
CREATE TABLE ticket (                                    -- prov:Activity (bundle)
  id                  uuid PRIMARY KEY,
  tenant_id           uuid NOT NULL REFERENCES tenant(id),
  key                 text NOT NULL,                     -- human key, e.g. 'DMF-1042'
  document_id         uuid NOT NULL REFERENCES document(id),
  kind                ticket_kind NOT NULL,
  status              ticket_status NOT NULL DEFAULT 'DRAFT',
  risk_level          smallint NOT NULL CHECK (risk_level BETWEEN 0 AND 3),
  title               text NOT NULL,
  opened_by           uuid NOT NULL REFERENCES agent(id),        -- Who
  opened_at           timestamptz NOT NULL DEFAULT now(),        -- When
  base_version_id     uuid REFERENCES document_version(id),      -- What (input)
  candidate_version_id uuid REFERENCES document_version(id),     -- proposed result
  target_modules      text[] NOT NULL DEFAULT '{}',              -- What (scope)
  approval_policy_id  uuid NOT NULL REFERENCES policy(id),       -- prov:hadPlan
  decision_id         uuid,                                      -- final Decision entity
  result_version_id   uuid REFERENCES document_version(id),      -- final Result entity
  closed_at           timestamptz,
  row_version         bigint NOT NULL DEFAULT 0,                 -- OCC for ticket state
  UNIQUE (tenant_id, key)
);

CREATE TABLE activity (
  id             uuid PRIMARY KEY,
  tenant_id      uuid NOT NULL REFERENCES tenant(id),
  ticket_id      uuid REFERENCES ticket(id),               -- dct:isPartOf
  type           activity_type NOT NULL,
  started_at     timestamptz NOT NULL,                     -- prov:startedAtTime
  ended_at       timestamptz,                              -- prov:endedAtTime
  informed_by    uuid REFERENCES activity(id),             -- prov:wasInformedBy
  idempotency_key text,
  UNIQUE (tenant_id, idempotency_key)
);

CREATE TABLE association (                               -- prov:qualifiedAssociation
  activity_id  uuid NOT NULL REFERENCES activity(id),
  agent_id     uuid NOT NULL REFERENCES agent(id),
  role         text NOT NULL,                            -- prov:hadRole: author/reviewer/verifier/...
  plan_id      uuid REFERENCES policy(id),               -- prov:hadPlan
  PRIMARY KEY (activity_id, agent_id, role)
);
CREATE TRIGGER association_immutable BEFORE UPDATE OR DELETE ON association
  FOR EACH ROW EXECUTE FUNCTION forbid_mutation();

CREATE TABLE usage (                                     -- prov:qualifiedUsage
  activity_id  uuid NOT NULL REFERENCES activity(id),
  entity_iri   text NOT NULL,                            -- urn:dmf:version:<id> etc.
  role         text NOT NULL,                            -- base/ours/theirs/criteria/evidence
  at_time      timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (activity_id, entity_iri, role)
);
CREATE TRIGGER usage_immutable BEFORE UPDATE OR DELETE ON usage
  FOR EACH ROW EXECUTE FUNCTION forbid_mutation();

ALTER TABLE module_revision  ADD FOREIGN KEY (generated_by) REFERENCES activity(id);
ALTER TABLE document_version ADD FOREIGN KEY (generated_by) REFERENCES activity(id);
ALTER TABLE policy           ADD FOREIGN KEY (generated_by) REFERENCES activity(id);

-- ---------------------------------------------------------------- decisions & approvals
CREATE TABLE approval (                                  -- one vote; prov:Entity
  id               uuid PRIMARY KEY,
  ticket_id        uuid NOT NULL REFERENCES ticket(id),
  activity_id      uuid NOT NULL REFERENCES activity(id),
  agent_id         uuid NOT NULL REFERENCES agent(id),
  role             text NOT NULL,
  outcome          decision_outcome NOT NULL,
  subject_manifest_root char(64) NOT NULL,               -- binds vote to exact content
  rationale        text,
  decided_at       timestamptz NOT NULL DEFAULT now(),
  UNIQUE (ticket_id, agent_id, subject_manifest_root)
);
CREATE TRIGGER approval_immutable BEFORE UPDATE OR DELETE ON approval
  FOR EACH ROW EXECUTE FUNCTION forbid_mutation();

CREATE TABLE decision (                                  -- aggregated outcome; prov:Entity
  id               uuid PRIMARY KEY,
  ticket_id        uuid NOT NULL UNIQUE REFERENCES ticket(id),
  generated_by     uuid NOT NULL REFERENCES activity(id),
  outcome          decision_outcome NOT NULL,
  policy_id        uuid NOT NULL REFERENCES policy(id),
  policy_sha256    char(64) NOT NULL,                    -- which rules were applied
  subject_manifest_root char(64) NOT NULL,
  approval_ids     uuid[] NOT NULL,                      -- prov:wasDerivedFrom approvals
  decided_at       timestamptz NOT NULL DEFAULT now()
);
CREATE TRIGGER decision_immutable BEFORE UPDATE OR DELETE ON decision
  FOR EACH ROW EXECUTE FUNCTION forbid_mutation();
ALTER TABLE ticket ADD FOREIGN KEY (decision_id) REFERENCES decision(id);

-- SoD: an approver may not be an author of the same ticket.
CREATE OR REPLACE FUNCTION check_separation_of_duties() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM association a JOIN activity act ON act.id = a.activity_id
     WHERE act.ticket_id = NEW.ticket_id AND a.agent_id = NEW.agent_id AND a.role = 'author'
  ) THEN
    RAISE EXCEPTION 'DMF-SOD: agent % authored ticket % and cannot approve it', NEW.agent_id, NEW.ticket_id;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER approval_sod BEFORE INSERT ON approval
  FOR EACH ROW EXECUTE FUNCTION check_separation_of_duties();

-- ---------------------------------------------------------------- verification
CREATE TABLE verification_run (                          -- prov:Entity (report) + activity link
  id                 uuid PRIMARY KEY,
  tenant_id          uuid NOT NULL REFERENCES tenant(id),
  ticket_id          uuid NOT NULL REFERENCES ticket(id),
  version_id         uuid NOT NULL REFERENCES document_version(id),
  manifest_root      char(64) NOT NULL,                  -- what exactly was tested
  criteria_policy_id uuid NOT NULL REFERENCES policy(id),
  generated_by       uuid NOT NULL REFERENCES activity(id),
  verdict            check_outcome NOT NULL,
  report_sha256      char(64) REFERENCES content_blob(sha256),
  finished_at        timestamptz NOT NULL
);
CREATE TRIGGER verification_run_immutable BEFORE UPDATE OR DELETE ON verification_run
  FOR EACH ROW EXECUTE FUNCTION forbid_mutation();

CREATE TABLE verification_result (
  run_id        uuid NOT NULL REFERENCES verification_run(id),
  criterion_id  text NOT NULL,                           -- AC-xxx
  blocking      boolean NOT NULL,
  outcome       check_outcome NOT NULL,
  evidence      jsonb NOT NULL DEFAULT '{}',
  PRIMARY KEY (run_id, criterion_id)
);
CREATE TRIGGER verification_result_immutable BEFORE UPDATE OR DELETE ON verification_result
  FOR EACH ROW EXECUTE FUNCTION forbid_mutation();

-- ---------------------------------------------------------------- releases (shadow/official)
CREATE TABLE release (
  id               uuid PRIMARY KEY,
  tenant_id        uuid NOT NULL REFERENCES tenant(id),
  document_id      uuid NOT NULL REFERENCES document(id),
  channel          release_channel NOT NULL,
  version_id       uuid NOT NULL REFERENCES document_version(id),
  manifest_root    char(64) NOT NULL,
  promoted_from    uuid REFERENCES release(id),          -- prov:alternateOf shadow release
  generated_by     uuid NOT NULL REFERENCES activity(id),
  gate_policy_id   uuid REFERENCES policy(id),
  status           release_status NOT NULL DEFAULT 'ACTIVE',  -- only mutable column
  created_at       timestamptz NOT NULL DEFAULT now(),
  CHECK (channel = 'SHADOW' OR (promoted_from IS NOT NULL AND gate_policy_id IS NOT NULL))
);
-- At most one ACTIVE release per (document, channel).
CREATE UNIQUE INDEX release_one_active ON release(document_id, channel) WHERE status = 'ACTIVE';

-- "Promote what you tested": an official release must carry the shadow release's exact bytes.
CREATE OR REPLACE FUNCTION check_promotion() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE src release;
BEGIN
  IF TG_OP = 'UPDATE' THEN
    IF (NEW.id, NEW.document_id, NEW.channel, NEW.version_id, NEW.manifest_root, NEW.promoted_from,
        NEW.generated_by, NEW.gate_policy_id)
       IS DISTINCT FROM
       (OLD.id, OLD.document_id, OLD.channel, OLD.version_id, OLD.manifest_root, OLD.promoted_from,
        OLD.generated_by, OLD.gate_policy_id) THEN
      RAISE EXCEPTION 'DMF-I1: only release.status may change';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.channel = 'OFFICIAL' THEN
    SELECT * INTO src FROM release WHERE id = NEW.promoted_from;
    IF src.channel <> 'SHADOW' OR src.manifest_root <> NEW.manifest_root
       OR src.document_id <> NEW.document_id THEN
      RAISE EXCEPTION 'DMF-PROMOTE: official release must equal its shadow release manifest';
    END IF;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER release_promotion BEFORE INSERT OR UPDATE ON release
  FOR EACH ROW EXECUTE FUNCTION check_promotion();
CREATE TRIGGER release_no_delete BEFORE DELETE ON release
  FOR EACH ROW EXECUTE FUNCTION forbid_mutation();

-- ---------------------------------------------------------------- I-3 restrict seal guard
CREATE OR REPLACE FUNCTION check_restrict_seal() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE parent_seal char(64); t ticket;
BEGIN
  IF NEW.parent_version_id IS NULL THEN RETURN NEW; END IF;
  SELECT restrict_seal INTO parent_seal FROM document_version WHERE id = NEW.parent_version_id;
  IF parent_seal = NEW.restrict_seal THEN RETURN NEW; END IF;

  SELECT tk.* INTO t FROM activity a JOIN ticket tk ON tk.id = a.ticket_id WHERE a.id = NEW.generated_by;
  IF t.kind = 'CORE_AMENDMENT' AND t.risk_level = 3 AND EXISTS (
       SELECT 1 FROM decision d WHERE d.ticket_id = t.id AND d.outcome = 'APPROVE') THEN
    RETURN NEW;
  END IF;
  -- ROLLBACK may restore an *earlier* seal only if it is a seal this document has had before.
  IF t.kind = 'ROLLBACK' AND EXISTS (
       SELECT 1 FROM document_version v WHERE v.document_id = NEW.document_id
          AND v.restrict_seal = NEW.restrict_seal) THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'DMF-I3: restrict seal changed without approved CORE_AMENDMENT (doc %)', NEW.document_id;
END $$;
CREATE TRIGGER version_restrict_seal BEFORE INSERT ON document_version
  FOR EACH ROW EXECUTE FUNCTION check_restrict_seal();

-- ---------------------------------------------------------------- I-2 optimistic head advance
-- Fast-forward only: the new version's parent must be the current head. Concurrent writers
-- that lose the CAS receive SQLSTATE 40001-like 'DMF409' and must rebase via three-way merge.
CREATE OR REPLACE FUNCTION advance_head(p_document uuid, p_expected_token bigint, p_new_version uuid)
RETURNS bigint LANGUAGE plpgsql AS $$
DECLARE new_token bigint; v document_version;
BEGIN
  SELECT * INTO v FROM document_version WHERE id = p_new_version AND document_id = p_document;
  IF NOT FOUND THEN RAISE EXCEPTION 'DMF404: version % not in document %', p_new_version, p_document; END IF;

  UPDATE document
     SET head_version_id = p_new_version, change_token = change_token + 1
   WHERE id = p_document
     AND change_token = p_expected_token
     AND head_version_id IS NOT DISTINCT FROM v.parent_version_id
  RETURNING change_token INTO new_token;

  IF new_token IS NULL THEN
    RAISE EXCEPTION 'DMF409: stale change token or non-fast-forward for document %', p_document
      USING ERRCODE = 'P0409', HINT = 'reload head, three-way merge, retry';
  END IF;
  RETURN new_token;
END $$;

-- ---------------------------------------------------------------- I-4 audit log
CREATE TABLE audit_event (
  chain_id     text NOT NULL,                            -- urn:dmf:doc:<id> | urn:dmf:tenant:<id>
  seq          bigint NOT NULL CHECK (seq >= 1),
  tenant_id    uuid NOT NULL REFERENCES tenant(id),
  prev_hash    char(64) NOT NULL,
  entry_hash   char(64) NOT NULL UNIQUE,                 -- sha256("dmf.audit/v1\0" || JCS(body))
  occurred_at  timestamptz NOT NULL,
  actor_iri    text NOT NULL,
  action       text NOT NULL,
  target_iri   text NOT NULL,
  ticket_id    uuid REFERENCES ticket(id),
  body         jsonb NOT NULL,                           -- exact JCS body that was hashed
  PRIMARY KEY (chain_id, seq)
);
CREATE TRIGGER audit_event_immutable BEFORE UPDATE OR DELETE ON audit_event
  FOR EACH ROW EXECUTE FUNCTION forbid_mutation();

CREATE OR REPLACE FUNCTION check_audit_link() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE prev_entry char(64);
BEGIN
  IF NEW.seq = 1 THEN
    IF NEW.prev_hash <> repeat('0', 64) THEN RAISE EXCEPTION 'DMF-I4: genesis prev_hash must be zero'; END IF;
    RETURN NEW;
  END IF;
  SELECT entry_hash INTO prev_entry FROM audit_event WHERE chain_id = NEW.chain_id AND seq = NEW.seq - 1;
  IF prev_entry IS NULL OR prev_entry <> NEW.prev_hash THEN
    RAISE EXCEPTION 'DMF-I4: audit chain % broken at seq %', NEW.chain_id, NEW.seq;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER audit_event_link BEFORE INSERT ON audit_event
  FOR EACH ROW EXECUTE FUNCTION check_audit_link();
-- Concurrency: two writers computing the same seq collide on the PK -> one retries.
-- Because the per-document chain is appended in the same transaction as advance_head,
-- the document's OCC already serializes writers of that chain.

CREATE TABLE audit_checkpoint (
  tenant_id            uuid NOT NULL REFERENCES tenant(id),
  checkpoint_no        bigint NOT NULL,
  prev_checkpoint_root char(64) NOT NULL,
  root                 char(64) NOT NULL,
  heads                jsonb NOT NULL,                   -- [[chain_id, seq, entry_hash], ...]
  key_id               text NOT NULL,
  signature            text NOT NULL,
  tsa_token            bytea,                            -- RFC 3161 timestamp token
  anchor_uri           text,                             -- s3 object-lock copy
  created_at           timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, checkpoint_no)
);
CREATE TRIGGER audit_checkpoint_immutable BEFORE UPDATE OR DELETE ON audit_checkpoint
  FOR EACH ROW EXECUTE FUNCTION forbid_mutation();

-- ---------------------------------------------------------------- lease fencing
-- Redis hands out monotonically increasing fencing tokens with each module lease.
-- The commit transaction runs:
--   INSERT ... ON CONFLICT (document_id, module_key) DO UPDATE SET last_fence = EXCLUDED.last_fence
--     WHERE lease_fence.last_fence <= EXCLUDED.last_fence
-- and aborts if no row was written: a writer whose lease expired (GC pause, partition)
-- and was superseded by a newer holder can never commit.
CREATE TABLE lease_fence (
  document_id  uuid NOT NULL REFERENCES document(id),
  module_key   text NOT NULL,
  last_fence   bigint NOT NULL,
  PRIMARY KEY (document_id, module_key)
);

-- ---------------------------------------------------------------- outbox (CDC -> Kafka)
CREATE TABLE outbox (
  id           bigserial PRIMARY KEY,
  tenant_id    uuid NOT NULL,
  topic        text NOT NULL,
  key          text NOT NULL,
  payload      jsonb NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------- I-5 row-level security
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['agent','policy','document','module','module_revision','document_version',
                           'ticket','activity','verification_run','release','audit_event','audit_checkpoint']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (tenant_id = dmf.current_tenant())
                    WITH CHECK (tenant_id = dmf.current_tenant())', t);
  END LOOP;
END $$;

-- ---------------------------------------------------------------- indexes
CREATE INDEX ON document_version (document_id, version_no DESC);
CREATE INDEX ON document_version (manifest_root);
CREATE INDEX ON ticket (document_id, status);
CREATE INDEX ON activity (ticket_id, started_at);
CREATE INDEX ON usage (entity_iri);
CREATE INDEX ON audit_event (ticket_id);
CREATE INDEX ON audit_event (tenant_id, occurred_at);
CREATE INDEX ON verification_run (ticket_id, manifest_root);
