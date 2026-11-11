// Fine-grained authorization (RBAC + ABAC) — evaluated by the PDP for every command.
// Entity types: DMF::Agent, DMF::Role, DMF::Document, DMF::Module, DMF::Ticket, DMF::Release
// Context: { tenant, ticket_risk, module_mutability, channel, mfa_age_seconds, ip_trusted }

// ---- tenant isolation (deny overrides everything)
forbid (principal, action, resource)
when { principal.tenant != resource.tenant };

// ---- read
permit (principal, action == DMF::Action::"read", resource is DMF::Document)
when {
  principal.clearance_rank >= resource.classification_rank &&
  (resource.channel == "OFFICIAL" || principal in DMF::Role::"editor" || principal in DMF::Role::"reviewer")
};

// ---- edit mutable modules: editors, only through an open ticket they are assigned to
permit (principal in DMF::Role::"editor", action == DMF::Action::"edit_module", resource is DMF::Module)
when {
  resource.mutability == "MUTABLE" &&
  context has ticket && context.ticket.status == "IN_PROGRESS" &&
  principal in context.ticket.assignees
};

// ---- restricted modules: document owner only
permit (principal, action == DMF::Action::"edit_module", resource is DMF::Module)
when {
  resource.mutability == "RESTRICTED" &&
  principal == resource.document.owner &&
  context has ticket && context.ticket.status == "IN_PROGRESS"
};

// ---- immutable core: never through edit_module; only amend_core with step-up auth
forbid (principal, action == DMF::Action::"edit_module", resource is DMF::Module)
when { resource.mutability == "IMMUTABLE_CORE" };

permit (principal in DMF::Role::"governance_board", action == DMF::Action::"amend_core", resource is DMF::Module)
when {
  context.ticket.kind == "CORE_AMENDMENT" &&
  context.mfa_age_seconds < 300
};

// ---- approvals: role must be allowed by approval policy level; never own ticket (SoD)
permit (principal, action == DMF::Action::"approve", resource is DMF::Ticket)
when { principal.role_names.containsAny(resource.allowed_approver_roles) };

forbid (principal, action == DMF::Action::"approve", resource is DMF::Ticket)
when { resource.authors.contains(principal) || resource.requester == principal };

// ---- promotion to OFFICIAL
permit (principal in DMF::Role::"release_manager", action == DMF::Action::"promote", resource is DMF::Release)
when { context.mfa_age_seconds < 900 && context.ip_trusted };

// ---- software agents: verification + shadow deploy only
permit (principal is DMF::SoftwareAgent, action in [DMF::Action::"verify", DMF::Action::"shadow_deploy"], resource);
forbid (principal is DMF::SoftwareAgent, action in [DMF::Action::"promote", DMF::Action::"amend_core"], resource);
