

package kms.algorithms;

import java.util.Arrays;
import java.util.List;

public enum GcpAlgorithm implements SupportedAlgorithmInterface {
  AES(Arrays.asList(128, 256));

  private final List<Integer> keySizes;

  public List<Integer> getKeySizes() {
    return this.keySizes;
  }

  GcpAlgorithm(List<Integer> keySizes) {
    this.keySizes = keySizes;
  }
}
