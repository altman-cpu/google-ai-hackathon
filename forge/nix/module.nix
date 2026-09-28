{ config, lib, pkgs, ... }:

# NixOS module for the forge API.
#
# Every operational knob is declarative, and the dangerous ones are guarded by
# assertions that fail at *evaluation* time -- before a single byte is
# deployed. You cannot accidentally ship a machine pointed at SEI mainnet, and
# you cannot put a secret in the Nix store, because both are rejected while the
# configuration is still being built.

let
  cfg = config.services.forge;
  inherit (lib) mkEnableOption mkOption mkIf types literalExpression;

  mainnetNetworks = [ "pacific-1" ];
  isMainnet = builtins.elem cfg.network mainnetNetworks;
in
{
  options.services.forge = {
    enable = mkEnableOption "the forge intent-to-code API";

    package = mkOption {
      type = types.package;
      default = pkgs.callPackage ./package.nix { };
      defaultText = literalExpression "pkgs.forge";
      description = "The forge package to run.";
    };

    # ---- network binding ------------------------------------------------

    listenAddress = mkOption {
      type = types.str;
      default = "127.0.0.1";
      example = "0.0.0.0";
      description = ''
        Address to bind. Defaults to loopback: the API is unauthenticated and
        will generate code for anyone who can reach it, so exposing it publicly
        should be a deliberate act, behind a reverse proxy that handles auth.
      '';
    };

    port = mkOption {
      type = types.port;
      default = 8787;
      description = "TCP port for the API.";
    };

    openFirewall = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Open {option}`services.forge.port` in the firewall. Left off by default
        for the same reason as {option}`listenAddress`.
      '';
    };

    # ---- pipeline behaviour ---------------------------------------------

    rigor = mkOption {
      type = types.enum [ "lax" "standard" "strict" "extreme" ];
      default = "strict";
      description = ''
        How hard the pipeline fails.

        - `lax`: warn about everything, gate nothing
        - `standard`: validation errors fail the build
        - `strict`: warnings become errors; builds must be digest-reproducible
        - `extreme`: also requires a PGP signature and a settled payment

        Defaults to `strict` here rather than `standard`: a long-running
        service should not be quietly emitting output it cannot reproduce.
      '';
    };

    stateDir = mkOption {
      type = types.str;
      default = "/var/lib/forge";
      description = "Working directory holding the iceberg object store.";
    };

    sourceDateEpoch = mkOption {
      type = types.int;
      default = 0;
      description = ''
        Value of `SOURCE_DATE_EPOCH`, the reproducible-builds timestamp. Leave
        at 0 unless you need generated artifacts to carry a real date; any
        change alters every downstream digest.
      '';
    };

    # ---- SEI ------------------------------------------------------------

    network = mkOption {
      type = types.enum [ "atlantic-2" "arctic-1" "pacific-1" ];
      default = "atlantic-2";
      description = ''
        SEI network. `pacific-1` is MAINNET and moves real funds; selecting it
        additionally requires {option}`services.forge.allowMainnet`.
      '';
    };

    allowMainnet = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Explicit consent to operate against SEI mainnet.

        Selecting a mainnet {option}`network` is deliberately not sufficient.
        Two independent options must agree before real value can move, so no
        single typo, merge, or copied snippet can do it alone.
      '';
    };

    payee = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "sei1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";
      description = ''
        SEI address that receives payment. This is a *receiving* address: forge
        never needs, and never accepts, the matching private key.
      '';
    };

    minConfirmations = mkOption {
      type = types.ints.unsigned;
      default = 1;
      description = ''
        Confirmations required before a payment counts as settled. Raise this
        for larger amounts, and especially on mainnet behind a public RPC
        endpoint, which can serve a stale or forked view.
      '';
    };

    lcdEndpoint = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "https://sei-rest.internal";
      description = ''
        Override the Cosmos REST endpoint. Strongly recommended for mainnet:
        public RPC is rate-limited and must not be trusted for finality.
      '';
    };

    evmRpcEndpoint = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Override the EVM JSON-RPC endpoint.";
    };

    # ---- signing --------------------------------------------------------

    gpgKey = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "0xDEADBEEFCAFEBABE";
      description = ''
        Key id or fingerprint used for detached manifest signatures. This
        names a key; it is not key material. The secret key itself lives in
        the service user's GnuPG home, managed outside Nix.
      '';
    };

    # ---- secrets --------------------------------------------------------

    environmentFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      example = "/run/secrets/forge.env";
      description = ''
        Path to an EnvironmentFile holding secrets such as `GEMINI_API_KEY`.

        This must be a path that exists on the deployed machine (from sops-nix,
        agenix, or similar) -- never a Nix path literal. Anything in the Nix
        store is world-readable, so a secret placed there is a published
        secret. The assertion below enforces this.
      '';
    };

    user = mkOption {
      type = types.str;
      default = "forge";
      description = "User account the service runs as.";
    };

    group = mkOption {
      type = types.str;
      default = "forge";
      description = "Group the service runs as.";
    };

    extraEnvironment = mkOption {
      type = types.attrsOf types.str;
      default = { };
      example = literalExpression ''{ FORGE_HTTP_TIMEOUT = "30"; }'';
      description = "Additional environment variables. Never put secrets here.";
    };
  };

  config = mkIf cfg.enable {

    # ---- evaluation-time guardrails -----------------------------------

    assertions = [
      {
        assertion = isMainnet -> cfg.allowMainnet;
        message = ''
          services.forge.network is "${cfg.network}", which is SEI MAINNET and
          involves real funds, but services.forge.allowMainnet is false.

          Set services.forge.allowMainnet = true; to confirm this is deliberate,
          or use "atlantic-2" (testnet).
        '';
      }
      {
        assertion = isMainnet -> (cfg.payee != null);
        message = ''
          services.forge.network is mainnet but no services.forge.payee is set.
          Payment requests would have no recipient.
        '';
      }
      {
        assertion = isMainnet -> (cfg.lcdEndpoint != null);
        message = ''
          services.forge.network is mainnet but services.forge.lcdEndpoint is
          unset, so settlement would be verified against a public, rate-limited
          RPC endpoint. Point this at a node you control before settling real
          value.
        '';
      }
      {
        assertion = (cfg.rigor == "extreme") -> (cfg.gpgKey != null);
        message = ''
          services.forge.rigor = "extreme" makes a detached PGP signature
          mandatory, but services.forge.gpgKey is null. Every build would fail.
        '';
      }
      {
        assertion = cfg.environmentFile == null
          || !(lib.hasPrefix builtins.storeDir (toString cfg.environmentFile));
        message = ''
          services.forge.environmentFile points into the Nix store, which is
          world-readable on every machine that has it. Use a runtime secret
          path instead (sops-nix, agenix, or a file provisioned out of band).
        '';
      }
      {
        assertion = cfg.listenAddress == "127.0.0.1" || cfg.listenAddress == "::1"
          || !cfg.openFirewall || cfg.payee == null || !isMainnet;
        message = ''
          services.forge is configured to listen on ${cfg.listenAddress} with the
          firewall open, on mainnet. The API is unauthenticated. Put it behind a
          reverse proxy that enforces authentication, or bind to loopback.
        '';
      }
    ];

    warnings =
      lib.optional (cfg.listenAddress != "127.0.0.1" && cfg.listenAddress != "::1") ''
        services.forge is listening on ${cfg.listenAddress}. The forge API has no
        authentication of its own -- anyone who can reach it can run builds.
      ''
      ++ lib.optional (isMainnet && cfg.minConfirmations < 2) ''
        services.forge is on mainnet with minConfirmations = ${toString cfg.minConfirmations}.
        Consider raising it before settling meaningful amounts.
      '';

    # ---- accounts -------------------------------------------------------

    users.users = lib.mkIf (cfg.user == "forge") {
      forge = {
        isSystemUser = true;
        group = cfg.group;
        home = cfg.stateDir;
        description = "forge service account";
      };
    };

    users.groups = lib.mkIf (cfg.group == "forge") { forge = { }; };

    networking.firewall.allowedTCPPorts = lib.mkIf cfg.openFirewall [ cfg.port ];

    # ---- service --------------------------------------------------------

    systemd.services.forge = {
      description = "forge intent-to-code API";
      documentation = [ "https://github.com/altman-cpu/google-ai-hackathon" ];
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];

      environment = {
        FORGE_WORKDIR = cfg.stateDir;
        FORGE_RIGOR = cfg.rigor;
        FORGE_SEI_NETWORK = cfg.network;
        FORGE_MIN_CONFIRMATIONS = toString cfg.minConfirmations;
        SOURCE_DATE_EPOCH = toString cfg.sourceDateEpoch;
        GNUPGHOME = "${cfg.stateDir}/gnupg";
      }
      // lib.optionalAttrs cfg.allowMainnet { FORGE_ALLOW_MAINNET = "1"; }
      // lib.optionalAttrs (cfg.payee != null) { FORGE_SEI_PAYEE = cfg.payee; }
      // lib.optionalAttrs (cfg.gpgKey != null) { FORGE_GPG_KEY = cfg.gpgKey; }
      // lib.optionalAttrs (cfg.lcdEndpoint != null) { FORGE_SEI_LCD = cfg.lcdEndpoint; }
      // lib.optionalAttrs (cfg.evmRpcEndpoint != null) { FORGE_SEI_EVM_RPC = cfg.evmRpcEndpoint; }
      // cfg.extraEnvironment;

      serviceConfig = {
        ExecStart = lib.escapeShellArgs [
          "${cfg.package}/bin/forge"
          "serve"
          "--host" cfg.listenAddress
          "--port" (toString cfg.port)
        ];

        User = cfg.user;
        Group = cfg.group;
        Restart = "on-failure";
        RestartSec = "5s";

        StateDirectory = "forge";
        StateDirectoryMode = "0750";
        WorkingDirectory = cfg.stateDir;

        EnvironmentFile = lib.mkIf (cfg.environmentFile != null) cfg.environmentFile;

        # ---- hardening --------------------------------------------------
        # forge reads intent documents, writes its own state, shells out to
        # gpg, and makes outbound HTTPS calls. It needs nothing else, so
        # everything else is taken away.
        DynamicUser = false;
        NoNewPrivileges = true;
        PrivateTmp = true;
        PrivateDevices = true;
        PrivateUsers = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        ProtectControlGroups = true;
        ProtectClock = true;
        ProtectHostname = true;
        ProtectProc = "invisible";
        ProcSubset = "pid";
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_UNIX" ];
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        SystemCallArchitectures = "native";
        SystemCallFilter = [ "@system-service" "~@privileged" "~@resources" ];
        CapabilityBoundingSet = [ "" ];
        AmbientCapabilities = [ "" ];
        UMask = "0077";

        ReadWritePaths = [ cfg.stateDir ];
      };
    };
  };
}
