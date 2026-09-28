{ lib
, python311Packages
, gnupg
, makeWrapper
}:

python311Packages.buildPythonApplication rec {
  pname = "forge";
  version = "0.1.0";
  pyproject = true;

  src = lib.cleanSourceWith {
    src = ../.;
    filter = path: type:
      let base = baseNameOf (toString path); in
      !(builtins.elem base [ ".forge" "out" "result" "__pycache__" ".pytest_cache" ]);
  };

  build-system = [ python311Packages.setuptools ];

  # Intentionally empty: forge is pure standard library at runtime. gnupg is
  # wrapped onto PATH below rather than being a Python dependency, because it
  # is an external binary that forge shells out to.
  dependencies = [ ];

  nativeBuildInputs = [ makeWrapper ];

  nativeCheckInputs = [ gnupg ];

  checkPhase = ''
    runHook preCheck
    export SOURCE_DATE_EPOCH=0
    export FORGE_SEI_NETWORK=atlantic-2
    # Never let a sandboxed test reach mainnet, even accidentally.
    unset FORGE_ALLOW_MAINNET
    PYTHONPATH="$PWD/src:$PWD:$PYTHONPATH" \
      ${python311Packages.python.interpreter} -m unittest discover -s tests -t . -v
    runHook postCheck
  '';

  postFixup = ''
    # gpg must be resolvable at runtime for manifest signing.
    wrapProgram $out/bin/forge \
      --prefix PATH : ${lib.makeBinPath [ gnupg ]}
  '';

  pythonImportsCheck = [
    "forge"
    "forge.cli"
    "forge.pipeline"
    "forge.payments.gateway"
    "forge.signing.manifest"
  ];

  meta = with lib; {
    description = "Intent-driven code design with SHA-256d commitments, PGP signatures, and SEI settlement";
    longDescription = ''
      forge turns a declarative network intent graph into generated code, commits
      to the result with a Bitcoin-style double-SHA-256 merkle root, signs the
      manifest with a detached OpenPGP signature, and prices the build against a
      published SEI catalog.

      It is non-custodial: forge never holds, reads, or transmits a private key.
      Payments are issued as requests and verified read-only on chain.
    '';
    homepage = "https://github.com/altman-cpu/google-ai-hackathon";
    license = licenses.mit;
    mainProgram = "forge";
    platforms = platforms.unix;
  };
}
