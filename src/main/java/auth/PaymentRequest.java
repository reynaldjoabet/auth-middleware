package auth;
import java.math.BigDecimal;

public record PaymentRequest(BigDecimal amount, String currency, String creditorIban) {
}