/*
 * Copyright 2021 YugabyteDB, Inc. and Contributors
 *
 * Licensed under the Polyform Free Trial License 1.0.0 (the "License"); you
 * may not use this file except in compliance with the License. You
 * may obtain a copy of the License at
 *
 * https://github.com/YugaByte/yugabyte-db/blob/master/licenses/
 *  POLYFORM-FREE-TRIAL-LICENSE-1.0.0.txt
 */

package kms.util;

/**
 * Minimal stand-in for the upstream YugabyteDB utility. Only KeyType is carried
 * over, since that is all the hashicorpvault classes in this package import.
 */
public class EncryptionAtRestUtil {

  /**
   * Distinguishes a key managed inside the KMS (the root/customer master key)
   * from a data key that the KMS wraps and hands back for local use.
   */
  public enum KeyType {
    CMK,
    DATA_KEY;
  }
}
