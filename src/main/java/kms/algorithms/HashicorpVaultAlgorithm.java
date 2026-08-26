
package kms.algorithms;

import java.util.Arrays;
import java.util.List;

public enum HashicorpVaultAlgorithm implements SupportedAlgorithmInterface {
  // Hashicorp vault uses AES GCM
  AES(Arrays.asList(128, 256));

  private final List<Integer> keySizes;

  public List<Integer> getKeySizes() {
    return this.keySizes;
  }

  HashicorpVaultAlgorithm(List<Integer> keySizes) {
    this.keySizes = keySizes;
  }
}
