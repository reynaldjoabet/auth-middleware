
package kms.algorithms;

import java.util.List;

/**
 * Should be implemented for each EncryptionAtRestService impl as an enum of supported encryption
 * algorithms
 */
public interface SupportedAlgorithmInterface {
  List<Integer> getKeySizes();

  String name();
}
