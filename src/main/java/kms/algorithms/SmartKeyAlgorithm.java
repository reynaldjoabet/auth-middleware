
package kms.algorithms;

import java.util.Arrays;
import java.util.List;

/**
 * The different encryption algorithms allowed and a mapping of encryption algorithm -> valid
 * encryption key sizes (bits)
 */
public enum SmartKeyAlgorithm implements SupportedAlgorithmInterface {
  AES(Arrays.asList(128, 192, 256));

  private final List<Integer> keySizes;

  public List<Integer> getKeySizes() {
    return this.keySizes;
  }

  SmartKeyAlgorithm(List<Integer> keySizes) {
    this.keySizes = keySizes;
  }
}
