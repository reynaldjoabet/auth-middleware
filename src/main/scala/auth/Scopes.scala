package auth
import io.github.iltotore.iron.*
import io.github.iltotore.iron.constraint.all.*

object Scopes {

  // ── Billing ───────────────────────────────────────────────────────────
  val billingInvoicesRead = ScopeToken("billing.invoices.read")
  val billingInvoicesCreate = ScopeToken("billing.invoices.create")
  val billingInvoicesUpdate = ScopeToken("billing.invoices.update")
  val billingInvoicesAdjust = ScopeToken("billing.invoices.adjust")
  val billingInvoicesCancel = ScopeToken("billing.invoices.cancel")
  val billingInvoicesReopen = ScopeToken("billing.invoices.reopen")
  val billingInvoicesManage = ScopeToken("billing.invoices.manage")
  val billingAuditRead = ScopeToken("billing.audit.read")
  val billingAuditExport = ScopeToken("billing.audit.export")

  // ── Payments: transactions ────────────────────────────────────────────
  val paymentsTransactionsRead = ScopeToken("payments.transactions.read")
  val paymentsTransactionsCreate = ScopeToken("payments.transactions.create")
  val paymentsTransactionsCapture = ScopeToken("payments.transactions.capture")
  val paymentsTransactionsVoid = ScopeToken("payments.transactions.void")
  val paymentsTransactionsRefund = ScopeToken("payments.transactions.refund")

  // ── Payments: authorizations ──────────────────────────────────────────
  val paymentsAuthorizationsRead = ScopeToken("payments.authorizations.read")
  val paymentsAuthorizationsCreate = ScopeToken(
    "payments.authorizations.create"
  )

  // ── Payments: methods ─────────────────────────────────────────────────
  val paymentsMethodsRead = ScopeToken("payments.methods.read")
  val paymentsMethodsCreate = ScopeToken("payments.methods.create")
  val paymentsMethodsUpdate = ScopeToken("payments.methods.update")
  val paymentsMethodsDelete = ScopeToken("payments.methods.delete")
  val paymentsMethodsManage = ScopeToken("payments.methods.manage")

  // ── Payments: settlements & disputes ──────────────────────────────────
  val paymentsSettlementsRead = ScopeToken("payments.settlements.read")
  val paymentsSettlementsClose = ScopeToken("payments.settlements.close")
  val paymentsDisputesRead = ScopeToken("payments.disputes.read")
  val paymentsDisputesRespond = ScopeToken("payments.disputes.respond")

  // ── Accounts ──────────────────────────────────────────────────────────
  val accountsRead = ScopeToken("accounts.read")
  val accountsBalancesRead = ScopeToken("accounts.balances.read")
  val accountsTransactionsRead = ScopeToken("accounts.transactions.read")
  val accountsTransactionsExport = ScopeToken("accounts.transactions.export")

  // ── Payment initiation (open banking) ─────────────────────────────────
  val paymentsInitiationsCreate = ScopeToken("payments.initiations.create")
  val paymentsInitiationsStatusRead = ScopeToken(
    "payments.initiations.status.read"
  )
  val paymentsInitiationsCancel = ScopeToken("payments.initiations.cancel")

  // ── Beneficiaries ─────────────────────────────────────────────────────
  val beneficiariesRead = ScopeToken("beneficiaries.read")
  val beneficiariesCreate = ScopeToken("beneficiaries.create")
  val beneficiariesDelete = ScopeToken("beneficiaries.delete")

  // ── Customers ─────────────────────────────────────────────────────────
  val customersProfileRead = ScopeToken("customers.profile.read")
  val customersProfileUpdate = ScopeToken("customers.profile.update")
  val customersIdentityRead = ScopeToken("customers.identity.read")
  val customersIdentityVerify = ScopeToken("customers.identity.verify")
  val customersContactsRead = ScopeToken("customers.contacts.read")
  val customersContactsUpdate = ScopeToken("customers.contacts.update")

  // ── Audit, risk & limits ──────────────────────────────────────────────
  val auditEventsRead = ScopeToken("audit.events.read")
  val auditEventsExport = ScopeToken("audit.events.export")
  val riskScoresRead = ScopeToken("risk.scores.read")
  val riskRulesRead = ScopeToken("risk.rules.read")
  val riskRulesManage = ScopeToken("risk.rules.manage")
  val limitsRead = ScopeToken("limits.read")
  val limitsUpdate = ScopeToken("limits.update")

  // ── Ledger & treasury ─────────────────────────────────────────────────
  val ledgerEntriesRead = ScopeToken("ledger.entries.read")
  val ledgerEntriesCreate = ScopeToken("ledger.entries.create")
  val ledgerEntriesAdjust = ScopeToken("ledger.entries.adjust")
  val treasuryBalancesRead = ScopeToken("treasury.balances.read")
  val treasuryTransfersCreate = ScopeToken("treasury.transfers.create")

  // ── Reports ───────────────────────────────────────────────────────────
  val reportsFinancialRead = ScopeToken("reports.financial.read")
  val reportsRegulatoryRead = ScopeToken("reports.regulatory.read")
  val reportsExportsCreate = ScopeToken("reports.exports.create")
  val reportsExportsRead = ScopeToken("reports.exports.read")

  val all: List[ScopeToken] = List(
    billingInvoicesRead,
    billingInvoicesCreate,
    billingInvoicesUpdate,
    billingInvoicesAdjust,
    billingInvoicesCancel,
    billingInvoicesReopen,
    billingInvoicesManage,
    billingAuditRead,
    billingAuditExport,
    paymentsTransactionsRead,
    paymentsTransactionsCreate,
    paymentsTransactionsCapture,
    paymentsTransactionsVoid,
    paymentsTransactionsRefund,
    paymentsAuthorizationsRead,
    paymentsAuthorizationsCreate,
    paymentsMethodsRead,
    paymentsMethodsCreate,
    paymentsMethodsUpdate,
    paymentsMethodsDelete,
    paymentsMethodsManage,
    paymentsSettlementsRead,
    paymentsSettlementsClose,
    paymentsDisputesRead,
    paymentsDisputesRespond,
    accountsRead,
    accountsBalancesRead,
    accountsTransactionsRead,
    accountsTransactionsExport,
    paymentsInitiationsCreate,
    paymentsInitiationsStatusRead,
    paymentsInitiationsCancel,
    beneficiariesRead,
    beneficiariesCreate,
    beneficiariesDelete,
    customersProfileRead,
    customersProfileUpdate,
    customersIdentityRead,
    customersIdentityVerify,
    customersContactsRead,
    customersContactsUpdate,
    auditEventsRead,
    auditEventsExport,
    riskScoresRead,
    riskRulesRead,
    riskRulesManage,
    limitsRead,
    limitsUpdate,
    ledgerEntriesRead,
    ledgerEntriesCreate,
    ledgerEntriesAdjust,
    treasuryBalancesRead,
    treasuryTransfersCreate,
    reportsFinancialRead,
    reportsRegulatoryRead,
    reportsExportsCreate,
    reportsExportsRead
  )

}
