package auth;

/**
 * Java-side constants for the scope tokens defined in the Scala
 * {@code auth.Scopes} object — the source of truth. Annotation members must
 * be compile-time constants, so the strings are duplicated here;
 * {@code ScopeConstantsParitySpec} fails the build if the two sets drift.
 *
 * <p>Generated mechanically from {@code Scopes.scala}; add new scopes there
 * first, then mirror them here (constant name = scope with {@code .} →
 * {@code _}, uppercased).
 */
public final class ScopeConstants {

    public static final String BILLING_INVOICES_READ = "billing.invoices.read";
    public static final String BILLING_INVOICES_CREATE = "billing.invoices.create";
    public static final String BILLING_INVOICES_UPDATE = "billing.invoices.update";
    public static final String BILLING_INVOICES_ADJUST = "billing.invoices.adjust";
    public static final String BILLING_INVOICES_CANCEL = "billing.invoices.cancel";
    public static final String BILLING_INVOICES_REOPEN = "billing.invoices.reopen";
    public static final String BILLING_INVOICES_MANAGE = "billing.invoices.manage";
    public static final String BILLING_AUDIT_READ = "billing.audit.read";
    public static final String BILLING_AUDIT_EXPORT = "billing.audit.export";
    public static final String PAYMENTS_TRANSACTIONS_READ = "payments.transactions.read";
    public static final String PAYMENTS_TRANSACTIONS_CREATE = "payments.transactions.create";
    public static final String PAYMENTS_TRANSACTIONS_CAPTURE = "payments.transactions.capture";
    public static final String PAYMENTS_TRANSACTIONS_VOID = "payments.transactions.void";
    public static final String PAYMENTS_TRANSACTIONS_REFUND = "payments.transactions.refund";
    public static final String PAYMENTS_AUTHORIZATIONS_READ = "payments.authorizations.read";
    public static final String PAYMENTS_AUTHORIZATIONS_CREATE = "payments.authorizations.create";
    public static final String PAYMENTS_METHODS_READ = "payments.methods.read";
    public static final String PAYMENTS_METHODS_CREATE = "payments.methods.create";
    public static final String PAYMENTS_METHODS_UPDATE = "payments.methods.update";
    public static final String PAYMENTS_METHODS_DELETE = "payments.methods.delete";
    public static final String PAYMENTS_METHODS_MANAGE = "payments.methods.manage";
    public static final String PAYMENTS_SETTLEMENTS_READ = "payments.settlements.read";
    public static final String PAYMENTS_SETTLEMENTS_CLOSE = "payments.settlements.close";
    public static final String PAYMENTS_DISPUTES_READ = "payments.disputes.read";
    public static final String PAYMENTS_DISPUTES_RESPOND = "payments.disputes.respond";
    public static final String ACCOUNTS_READ = "accounts.read";
    public static final String ACCOUNTS_BALANCES_READ = "accounts.balances.read";
    public static final String ACCOUNTS_TRANSACTIONS_READ = "accounts.transactions.read";
    public static final String ACCOUNTS_TRANSACTIONS_EXPORT = "accounts.transactions.export";
    public static final String PAYMENTS_INITIATIONS_CREATE = "payments.initiations.create";
    public static final String PAYMENTS_INITIATIONS_STATUS_READ = "payments.initiations.status.read";
    public static final String PAYMENTS_INITIATIONS_CANCEL = "payments.initiations.cancel";
    public static final String BENEFICIARIES_READ = "beneficiaries.read";
    public static final String BENEFICIARIES_CREATE = "beneficiaries.create";
    public static final String BENEFICIARIES_DELETE = "beneficiaries.delete";
    public static final String CUSTOMERS_PROFILE_READ = "customers.profile.read";
    public static final String CUSTOMERS_PROFILE_UPDATE = "customers.profile.update";
    public static final String CUSTOMERS_IDENTITY_READ = "customers.identity.read";
    public static final String CUSTOMERS_IDENTITY_VERIFY = "customers.identity.verify";
    public static final String CUSTOMERS_CONTACTS_READ = "customers.contacts.read";
    public static final String CUSTOMERS_CONTACTS_UPDATE = "customers.contacts.update";
    public static final String AUDIT_EVENTS_READ = "audit.events.read";
    public static final String AUDIT_EVENTS_EXPORT = "audit.events.export";
    public static final String RISK_SCORES_READ = "risk.scores.read";
    public static final String RISK_RULES_READ = "risk.rules.read";
    public static final String RISK_RULES_MANAGE = "risk.rules.manage";
    public static final String LIMITS_READ = "limits.read";
    public static final String LIMITS_UPDATE = "limits.update";
    public static final String LEDGER_ENTRIES_READ = "ledger.entries.read";
    public static final String LEDGER_ENTRIES_CREATE = "ledger.entries.create";
    public static final String LEDGER_ENTRIES_ADJUST = "ledger.entries.adjust";
    public static final String TREASURY_BALANCES_READ = "treasury.balances.read";
    public static final String TREASURY_TRANSFERS_CREATE = "treasury.transfers.create";
    public static final String REPORTS_FINANCIAL_READ = "reports.financial.read";
    public static final String REPORTS_REGULATORY_READ = "reports.regulatory.read";
    public static final String REPORTS_EXPORTS_CREATE = "reports.exports.create";
    public static final String REPORTS_EXPORTS_READ = "reports.exports.read";

    private ScopeConstants() {}
}
