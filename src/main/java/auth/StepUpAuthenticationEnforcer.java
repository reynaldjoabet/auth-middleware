package auth;
import com.nimbusds.jwt.JWTClaimsSet;
import java.time.Instant;
import java.util.Date;

public class StepUpAuthenticationEnforcer {

	private static final String HIGH_RISK_ACR = "urn:openbanking:psd2:sca";
	private static final long MAX_AUTH_AGE_SECONDS = 300; // 5 min for payments

	public enum AuthDecision {
		ALLOW, REQUIRE_STEP_UP
	}

	public AuthDecision evaluate(JWTClaimsSet claims, PaymentRequest payment) throws java.text.ParseException {
		String acr = claims.getStringClaim("acr");
		// getDateClaim handles the NumericDate encoding (a Long in a parsed
		// claims set) — a raw (Date) cast would throw ClassCastException.
		Date authTime = claims.getDateClaim("auth_time");

		boolean scaPerformed = HIGH_RISK_ACR.equals(acr);
		boolean authTimeFresh = authTime != null
				&& authTime.toInstant().isAfter(Instant.now().minusSeconds(MAX_AUTH_AGE_SECONDS));
		boolean highRiskAmount = payment.amount().compareTo(new java.math.BigDecimal("100")) > 0;

		if (highRiskAmount && (!scaPerformed || !authTimeFresh)) {
			return AuthDecision.REQUIRE_STEP_UP;
		}
		return AuthDecision.ALLOW;
	}

	/**
	 * Returns the WWW-Authenticate header value per RFC 9470. Client parses this
	 * and re-triggers authorization with acr_values.
	 */
	public String buildStepUpChallenge(String resourceId) {
		// error=insufficient_user_authentication signals step-up required
		return "Bearer error=\"insufficient_user_authentication\"," + "error_description=\"Payment requires SCA\","
				+ "acr_values=\"" + HIGH_RISK_ACR + "\"," + "max_age=\"0\"," // force fresh auth — no re-use of old
																				// session
				+ "resource=\"" + resourceId + "\"";
	}
}