{ pkgs ? import <nixpkgs> {} }:

let
  python = pkgs.python311;
in
pkgs.mkShell {
  buildInputs = [
    python
    python.pkgs.tqdm
    python.pkgs.pip
    pkgs.git
  ];

  shellHook = ''
    # Create venv if it does not exist
    if [ ! -d .venv ]; then
      echo "Creating virtual environment..."
      ${python.interpreter} -m venv .venv
    fi

    source .venv/bin/activate

    pip install --upgrade pip setuptools wheel || {
      echo "WARNING: pip tooling upgrade failed"
    }

    if [ -d lib/czds ]; then
      echo "Installing czds (editable)..."
      pip install -e lib/czds || {
        echo "ERROR: czds install failed"
        echo "Check that lib/czds contains a valid setup.py or pyproject.toml"
      }
    else
      echo "WARNING: lib/czds submodule not found"
      echo "You forget?: git submodule update --init --recursive ?"
    fi

    echo "Python environment ready."
  '';
}
