{
  lib,
  stdenvNoCC,
  nodejs_24,
  makeWrapper,
}:
stdenvNoCC.mkDerivation {
  pname = "t3router";
  version = "0.1.0";
  src = lib.cleanSource ./.;
  nativeBuildInputs = [ makeWrapper ];
  nativeCheckInputs = [ nodejs_24 ];
  dontConfigure = true;
  dontBuild = true;
  doCheck = true;
  checkPhase = ''
    runHook preCheck
    node --check src/provision.mjs
    node --check src/cli.mjs
    node --disable-warning=ExperimentalWarning --test test/*.test.mjs
    node --disable-warning=ExperimentalWarning test/mutation.mjs
    runHook postCheck
  '';
  installPhase = ''
    runHook preInstall
    mkdir -p $out/lib/t3router $out/bin
    cp -r src $out/lib/t3router/
    makeWrapper ${nodejs_24}/bin/node $out/bin/t3router \
      --add-flags "$out/lib/t3router/src/cli.mjs"
    runHook postInstall
  '';
  meta = {
    description = "Version-pinned, offline provisioning of native T3 Code environment links";
    homepage = "https://github.com/zeroknots/t3router";
    license = lib.licenses.mit;
    mainProgram = "t3router";
    platforms = lib.platforms.linux;
  };
}
