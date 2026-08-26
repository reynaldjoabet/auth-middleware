
package kms.algorithms;

import java.util.Arrays;
import java.util.List;

public enum AzuAlgorithm implements SupportedAlgorithmInterface {
  RSA(Arrays.asList(2048, 3072, 4096));

  private final List<Integer> keySizes;

  public List<Integer> getKeySizes() {
    return this.keySizes;
  }

  AzuAlgorithm(List<Integer> keySizes) {
    this.keySizes = keySizes;
  }
}
