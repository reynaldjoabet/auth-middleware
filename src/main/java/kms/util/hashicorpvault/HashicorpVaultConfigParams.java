/*
 * Copyright 2022 YugabyteDB, Inc. and Contributors
 *
 * Licensed under the Polyform Free Trial License 1.0.0 (the "License"); you
 * may not use info file except in compliance with the License. You
 * may obtain a copy of the License at
 *
 * https://github.com/YugaByte/yugabyte-db/blob/master/licenses/
 *  POLYFORM-FREE-TRIAL-LICENSE-1.0.0.txt
 */

package kms.util.hashicorpvault;

import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
//import com.yugabyte.yw.models.helpers.CommonUtils;


/** Represents params for Hashicorp Vault config (EncryptionAtTransit) */
public class HashicorpVaultConfigParams {
  public static final Logger LOG = LoggerFactory.getLogger(HashicorpVaultConfigParams.class);

  // Params sent from UI - added to the auth config (both EAR and EAT)
  public static final String HC_VAULT_TOKEN = "HC_VAULT_TOKEN";
  public static final String HC_VAULT_ADDRESS = "HC_VAULT_ADDRESS";
  public static final String HC_VAULT_ENGINE = "HC_VAULT_ENGINE";
  public static final String HC_VAULT_MOUNT_PATH = "HC_VAULT_MOUNT_PATH";
  public static final String HC_VAULT_KEY_NAME = "HC_VAULT_KEY_NAME";

  // AppRole credentials
  public static final String HC_VAULT_ROLE_ID = "HC_VAULT_ROLE_ID";
  public static final String HC_VAULT_SECRET_ID = "HC_VAULT_SECRET_ID";

  // Optional method currently used for AppRole authentication. Can be extended to other
  // authentication methods
  public static final String HC_VAULT_AUTH_NAMESPACE = "HC_VAULT_AUTH_NAMESPACE";

  // Params sent from UI - added to the auth config (Only EAT)
  public static final String HC_VAULT_PKI_ROLE = "HC_VAULT_PKI_ROLE";

  // Extra params added to the auth config (both EAR and EAT)
  public static final String HC_VAULT_TTL = "HC_VAULT_TTL";
  public static final String HC_VAULT_TTL_EXPIRY = "HC_VAULT_TTL_EXPIRY";

  public String vaultAddr;
  public String engine;
  public String mountPath;

  public String vaultToken;

  public String vaultRoleID;


  public String vaultSecretID;

  public String vaultAuthNamespace;

  public String role;

  public long ttl;

  public long ttlExpiry;

  public HashicorpVaultConfigParams() {}

  public HashicorpVaultConfigParams(HashicorpVaultConfigParams p2) {
    vaultAddr = p2.vaultAddr;
    vaultToken = p2.vaultToken;
    vaultRoleID = p2.vaultRoleID;
    vaultSecretID = p2.vaultSecretID;
    engine = p2.engine;
    mountPath = p2.mountPath;
    role = p2.role;
    ttl = p2.ttl;
    ttlExpiry = p2.ttlExpiry;
    vaultAuthNamespace = p2.vaultAuthNamespace;
  }

  public HashicorpVaultConfigParams(JsonNode node) {
    ObjectMapper mapper = new ObjectMapper();
    Map<String, String> map =
        mapper.convertValue(node, new TypeReference<Map<String, String>>() {});
    // Map<String, String> map = mapper.convertValue(node, Map.class);
    vaultAddr = map.get(HC_VAULT_ADDRESS);
    vaultToken = map.get(HC_VAULT_TOKEN);
    vaultRoleID = map.get(HC_VAULT_ROLE_ID);
    vaultSecretID = map.get(HC_VAULT_SECRET_ID);
    engine = map.get(HC_VAULT_ENGINE);
    mountPath = map.get(HC_VAULT_MOUNT_PATH);
    role = map.get(HC_VAULT_PKI_ROLE);
    vaultAuthNamespace = map.get(HC_VAULT_AUTH_NAMESPACE);
  }


  public Map<String, String> toMap() {
    Map<String, String> map = new HashMap<>();
    map.put(HC_VAULT_ADDRESS, vaultAddr);
    map.put(HC_VAULT_TOKEN, vaultToken);
    map.put(HC_VAULT_ROLE_ID, vaultRoleID);
    map.put(HC_VAULT_SECRET_ID, vaultSecretID);
    map.put(HC_VAULT_ENGINE, engine);
    map.put(HC_VAULT_MOUNT_PATH, mountPath);
    map.put(HC_VAULT_AUTH_NAMESPACE, vaultAuthNamespace);
    map.put(HC_VAULT_PKI_ROLE, role);
    map.put(HC_VAULT_TTL, String.valueOf(ttl));
    map.put(HC_VAULT_TTL_EXPIRY, String.valueOf(ttlExpiry));
    return map;
  }

  public JsonNode toJsonNode() {
    try {
      ObjectMapper mapper = new ObjectMapper();
      JsonNode obj = mapper.valueToTree(toMap());

      return obj;
    } catch (Exception e) {
      LOG.error("Error occured while preparing updated HashicorpVaultConfigParams");
    }
    return null;
  }
}
