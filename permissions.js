/*
  BOUESTI Vote — roles and permissions.

  Each administrator has exactly one role, and each role holds only the
  permissions its duties need (least privilege). The split is deliberate:

    Electoral Officer   runs the election: candidates, voters, status,
                        announcements, accounts. Cannot touch backups.
                        Gives the SECOND approval before results go public.
    Results Officer     counts and signs: prepares the tally report, runs
                        the supervised comparison. Cannot edit candidates
                        or voters, and cannot publish alone.
    Technical Support   keeps the system healthy: backups, restoration
                        drills, audit copy, incidents. Cannot see voter
                        details or results, and cannot change the election.

  Two-person rule: a report is prepared by the Results Officer and made
  public by a DIFFERENT administrator holding results.approve.

  The browser only uses these lists to hide buttons. Every API route
  checks them again on the server.
*/

"use strict";

const ROLES = {
  electoral_officer: {
    label: "Electoral Officer",
    summary: "Runs the election and approves publication of results.",
    permissions: [
      "election.view", "election.manage", "announcements.manage",
      "voters.view", "voters.manage",
      "stats.view", "settings.manage", "mode.manage",
      "results.view", "results.approve", "results.compare",
      "audit.view", "audit.export",
      "admins.view", "admins.manage",
      "ops.view", "reports.view", "reports.manage",
      "incidents.view", "incidents.manage"
    ]
  },

  results_officer: {
    label: "Results Officer",
    summary: "Prepares and signs the tally report and verifies it against the database.",
    permissions: [
      "election.view", "stats.view",
      "results.view", "results.prepare", "results.compare",
      "audit.view", "audit.export",
      "ops.view", "incidents.view", "incidents.manage"
    ]
  },

  technical_support: {
    label: "Technical Support Officer",
    summary: "Operates backups, restoration drills, monitoring and incident response.",
    permissions: [
      "election.view", "stats.view",
      "audit.view", "audit.export",
      "ops.view", "ops.manage",
      "reports.view", "reports.manage",
      "incidents.view", "incidents.manage"
    ]
  }
};

const ROLE_KEYS = Object.keys(ROLES);

function isRole(value) {
  return ROLE_KEYS.includes(value);
}

function permissionsFor(role) {
  return ROLES[role] ? [...ROLES[role].permissions] : [];
}

function can(role, permission) {
  return Boolean(ROLES[role] && ROLES[role].permissions.includes(permission));
}

function roleLabel(role) {
  return ROLES[role] ? ROLES[role].label : role;
}

module.exports = { ROLES, ROLE_KEYS, isRole, permissionsFor, can, roleLabel };
