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

package kms.util.hashicorpvault;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.slf4j.LoggerFactory;

import com.bettercloud.vault.VaultException;

import io.ebean.annotation.EnumValue;
import kms.util.EncryptionAtRestUtil.KeyType;

/**
 * Provides abstraction for functionality which allows us to perform operations on Hashicorp Vault
 * Secret Engine The secret engine is used to encrypt / decrypt universe keys
 */
public abstract class VaultSecretEngineBase {
  public static final Logger LOG = LoggerFactory.getLogger(VaultTransit.class);

  /**
   * com.bettercloud.vault.api.mounts.MountTypes enum has all types of secret engine Currently we
   * are using only following
   */
  public enum KMSEngineType {
    @EnumValue("transit") // only supported use case so far
    TRANSIT,

    @EnumValue("gcpkms") // not supported yet
    GCPKMS,

    @EnumValue("keymgmt") // not supported yet
    KEYMGMT;

    /** These strings are used in forming path. The same goes to the vault library. */
    public String toString() {
      switch (this) {
        case TRANSIT:
          return "transit";
        case GCPKMS:
          return "gcpkms";
        case KEYMGMT:
          return "keymgmt";
        default:
          return null;
      }
    }
  }

  /** Operations enum : key operations related to usage of secret engine keys */
  public enum VaultOperations {
    @EnumValue("keys")
    KEYS,

    @EnumValue("encrypt")
    ENCRYPT,

    @EnumValue("decrypt")
    DECRYPT,

    @EnumValue("rotate")
    ROTATE,

    @EnumValue("rewrap")
    RERWAP;

    /** These strings are used in forming path. The same goes to the vault library. */
    public String toString() {
      switch (this) {
        case KEYS:
          return "keys";
        case ENCRYPT:
          return "encrypt";
        case DECRYPT:
          return "decrypt";
        case ROTATE:
          return "rotate";
        case RERWAP:
          return "rewrap";
        default:
          return null;
      }
    }
  }

  KMSEngineType engineType;
  String mountPath;
  KeyType eKeyType;

  //VaultAccessor vAccessor;

  /**
   * Provides abstraction for HC Vault KMS engines.
   *
   * @param vault
   * @param type
   * @param mPath mount path to the secret engine, MUST END IN '/'
   * @param kType
   */
  public VaultSecretEngineBase(
       KMSEngineType type, String mPath, KeyType kType) {
    engineType = type;
    mountPath = mPath;
    eKeyType = kType;
    //vAccessor = vaultAccessor;

    checkForEngineType();
  }


  /**
   * @param basePath mount path to the secret engine (with mount name), MUST END IN '/'
   * @param op
   * @param keyName
   * @return full path built using params
   */
  public static String buildPath(String basePath, VaultOperations op, String keyName) {
    String path = basePath + op.toString() + "/" + keyName;
    LOG.debug("Generating path : {}", path);
    return path;
  }

  public String buildPath(VaultOperations op, String keyName) {
    String path = mountPath + op.toString() + "/" + keyName;
    LOG.debug("Generating path : {}", path);
    return path;
  }

  public abstract void checkForPermissions() throws Exception;

}
