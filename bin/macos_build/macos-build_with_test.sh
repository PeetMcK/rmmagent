#!/bin/bash
# rmmagent macOS Build & Test Script v2
# Version: 2.0.0
# Builds, signs, notarizes rmmagent with optional Tactical RMM execution
#
# Features:
# - Build for Intel (amd64), ARM (arm64), or Universal binary
# - Optional code signing and notarization
# - Execute Tactical RMM agent with full parameter support
#
# Usage:
#   sudo -E ./bin/macos_build/macos-build_with_test.sh --arch universal --trmm-exec
#   sudo -E ./bin/macos_build/macos-build_with_test.sh --arch arm64 --trmm-mode install --trmm-api https://api.example.com

set -e  # Exit on error

# Get the repository root directory
# Script is in bin/macos_build/, repo is 2 levels up
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
REPO_DIR="$( cd "$SCRIPT_DIR/../.." && pwd )"
cd "$REPO_DIR"

#==============================================================================
# DEFAULT CONFIGURATION
#==============================================================================

ARCH="universal"                    # Default: universal (also: amd64, arm64)
SKIP_BUILD="no"                     # Skip build step (use existing binary)
SKIP_SIGN="no"                      # Skip signing step
SKIP_NOTARY="no"                    # Skip notarization step
SKIP_GIT_PULL="yes"                 # Skip git pull before building
DEPLOY_BUILD="yes"				# Checks for tacticalagent.plist LaunchDaemon. Unloads, copies build over /opt/tacticalagent/tacticalagent reloads  tacticalagent.plist LaunchDaemon.
TRMM_EXEC="no"                      # Execute the TRMM agent at the end of the build process with TRMM-* inputs
TRMM_MODE=""                        # TRMM command: '-m install' or '-m svc'
TRMM_API=""                         # TRMM server api `--api https://api.example.com`
TRMM_CLIENT=""                      # TRMM Client-ID `--client-id 1`
TRMM_SITE=""                        # TRMM Site-ID `--site-id 1`
TRMM_AGENT=""                       # TRMM Agent-Type `--agent-type workstation`
TRMM_AUTH=""                        # TRMM Auth `--auth <token>`

#==============================================================================
# PARSE COMMAND LINE ARGUMENTS
#==============================================================================

while [[ $# -gt 0 ]]; do
    case $1 in
        --arch)
            ARCH="$2"
            shift 2
            ;;
        --skip-build)
            SKIP_BUILD="yes"
            shift
            ;;
        --skip-sign)
            SKIP_SIGN="yes"
            shift
            ;;
        --skip-notary)
            SKIP_NOTARY="yes"
            shift
            ;;
        --skip-deploy)
            DEPLOY_BUILD="no"
            shift
            ;;
        --git-pull)
            SKIP_GIT_PULL="no"
            shift
            ;;
        --trmm-exec)
            TRMM_EXEC="yes"
            shift
            ;;
        --trmm-mode)
            TRMM_MODE="$2"
            TRMM_EXEC="yes"  # Auto-enable execution if mode is specified
            shift 2
            ;;
        --trmm-api)
            TRMM_API="$2"
            shift 2
            ;;
        --trmm-client-id)
            TRMM_CLIENT="$2"
            shift 2
            ;;
        --trmm-site-id)
            TRMM_SITE="$2"
            shift 2
            ;;
        --trmm-agent-type)
            TRMM_AGENT="$2"
            shift 2
            ;;
        --trmm-auth)
            TRMM_AUTH="$2"
            shift 2
            ;;
        --help)
            echo "Usage: sudo [-E] $0 [OPTIONS]"
            echo ""
            echo "rmmagent Testing Script v2 - Build and deploy with Tactical RMM installation"
            echo ""
            echo "Note: Use 'sudo -E' when signing or notarizing to preserve environment variables:"
            echo "      - MACOS_SIGN_CERT (for code signing)"
            echo "      The -E flag preserves your user environment when running as root."
            echo ""
            echo "Build Options:"
            echo "  --arch <amd64|arm64|universal>  Architecture to build (default: universal)"
            echo "                                    amd64 = Intel x86_64"
            echo "                                    arm64 = Apple Silicon ARM64"
            echo "                                    universal = Universal binary (Intel + ARM)"
            echo "  --skip-build                    Skip build step, use existing binary"
            echo "  --skip-sign                     Skip signing step"
            echo "  --skip-notary                   Skip notarization step"
            echo "  --skip-deploy                   Skip deployment to /opt/tacticalagent/"
            echo "  --git-pull                      Pull latest changes before building"
            echo ""
            echo "Tactical RMM Installation Options:"
            echo "  --trmm-exec                     Execute tacticalagent installation after build"
            echo "  --trmm-mode <mode>              TRMM mode (auto-enables --trmm-exec):"
            echo "                                    install - Install and configure agent"
            echo "                                    svc     - Run as service"
            echo "  --trmm-api <url>                TRMM server API URL"
            echo "                                    Example: https://api.artichoke.tech"
            echo "  --trmm-client-id <id>           TRMM Client ID (numeric)"
            echo "  --trmm-site-id <id>             TRMM Site ID (numeric)"
            echo "  --trmm-agent-type <type>        TRMM Agent Type"
            echo "                                    workstation or server"
            echo "  --trmm-auth <token>             TRMM Authentication token"
            echo ""
            echo "Command Details:"
            echo "  The final command will be constructed as:"
            echo "    /path/to/tacticalagent -m <mode> --api <url> --client-id <id> --site-id <id> \\"
            echo "      --agent-type <type> --auth <token>"
            echo ""
            echo "Examples:"
            echo "  # Build, sign, and notarize (requires MACOS_SIGN_CERT and sudo -E)"
            echo "  export MACOS_SIGN_CERT=\"Developer ID Application: Your Name (TEAMID)\""
            echo "  sudo -E $0 --arch universal"
            echo ""
            echo "  # Build and install with full TRMM configuration"
            echo "  sudo -E $0 --arch universal --trmm-mode install \\"
            echo "    --trmm-api https://api.artichoke.tech \\"
            echo "    --trmm-client-id 1 --trmm-site-id 1 \\"
            echo "    --trmm-agent-type workstation \\"
            echo "    --trmm-auth a287d5f100b2d3642003ed624fdba943fdb6c0b74cbe3e1fa0318a328016d066"
            echo ""
            echo "  # Build only without signing or notarization"
            echo "  sudo $0 --arch universal --skip-sign --skip-notary"
            exit 0
            ;;
        *)
            echo "Error: Unknown option $1"
            echo "Run with --help for usage information"
            exit 1
            ;;
    esac
done

#==============================================================================
# VALIDATE CONFIGURATION
#==============================================================================

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run as root (use sudo)"
    exit 1
fi

# Validate ARCH
if [[ "$ARCH" != "amd64" && "$ARCH" != "arm64" && "$ARCH" != "universal" ]]; then
    echo "Error: Invalid ARCH '$ARCH'. Must be amd64, arm64, or universal"
    exit 1
fi

# Validate TRMM_MODE if set
if [ -n "$TRMM_MODE" ]; then
    if [[ "$TRMM_MODE" != "install" && "$TRMM_MODE" != "svc" ]]; then
        echo "Error: Invalid TRMM_MODE '$TRMM_MODE'."
        echo "Valid modes: install, svc"
        exit 1
    fi
fi

# Validate signing certificate if signing is enabled
if [ "$SKIP_SIGN" = "no" ]; then
    if [ -z "$MACOS_SIGN_CERT" ]; then
        echo "Error: MACOS_SIGN_CERT environment variable not set"
        echo ""
        echo "Signing is enabled (SKIP_SIGN=no) but no certificate is configured."
        echo ""
        echo "Solutions:"
        echo "  1. Set the certificate and run with sudo -E:"
        echo "     export MACOS_SIGN_CERT=\"Developer ID Application: Your Name (TEAMID)\""
        echo "     sudo -E $0"
        echo ""
        echo "     Note: The -E flag preserves your environment variables when using sudo."
        echo "           Without -E, sudo creates a new environment without MACOS_SIGN_CERT."
        echo ""
        echo "  2. Set the certificate in the sudo command:"
        echo "     sudo MACOS_SIGN_CERT=\"Developer ID Application: ...\" $0"
        echo ""
        echo "  3. Skip signing with --skip-sign flag:"
        echo "     sudo $0 --skip-sign"
        echo ""
        echo "To list available certificates:"
        echo "  security find-identity -v -p codesigning"
        exit 1
    fi

    # Verify the certificate exists in keychain
    if ! security find-identity -v -p codesigning | grep -q "$MACOS_SIGN_CERT"; then
        echo "Error: Certificate not found in keychain"
        echo ""
        echo "Certificate specified: $MACOS_SIGN_CERT"
        echo ""
        echo "Available certificates:"
        security find-identity -v -p codesigning
        echo ""
        echo "Please verify the certificate name matches exactly."
        exit 1
    fi

    echo "✓ Code signing certificate verified: $MACOS_SIGN_CERT"
fi

# Validate notarization keychain profile if notarization is enabled
if [ "$SKIP_NOTARY" = "no" ]; then
    KEYCHAIN_PROFILE="rmmagent-notary"

    if ! xcrun notarytool history --keychain-profile "$KEYCHAIN_PROFILE" &>/dev/null; then
        echo "Error: Keychain profile '$KEYCHAIN_PROFILE' not found"
        echo ""
        echo "Notarization is enabled (SKIP_NOTARY=no) but keychain profile is not configured."
        echo ""
        echo "Solutions:"
        echo "  1. Set up the keychain profile once with:"
        echo "     xcrun notarytool store-credentials \"$KEYCHAIN_PROFILE\" \\"
        echo "       --apple-id \"developer@example.com\" \\"
        echo "       --team-id \"TEAMID\" \\"
        echo "       --password \"xxxx-xxxx-xxxx-xxxx\""
        echo ""
        echo "  2. Skip notarization with --skip-notary flag:"
        echo "     sudo -E $0 --skip-notary"
        echo ""
        echo "     Note: Use sudo -E to preserve your environment variables."
        echo ""
        echo "Get credentials:"
        echo "  - Apple ID: Your Apple Developer account email"
        echo "  - Team ID: https://developer.apple.com/account (Membership section)"
        echo "  - Password: https://appleid.apple.com → Security → App-Specific Passwords"
        exit 1
    fi

    echo "✓ Notarization keychain profile verified: $KEYCHAIN_PROFILE"
fi

# Print blank line after validation checks
if [ "$SKIP_SIGN" = "no" ] || [ "$SKIP_NOTARY" = "no" ]; then
    echo ""
fi

#==============================================================================
# DETERMINE BINARY PATH AND BUILD ARCH
#==============================================================================

if [ "$ARCH" = "amd64" ]; then
    BINARY_PATH="build/Output/macos/amd64/rmmagent"
    ARCH_DESC="Intel x86-64"
elif [ "$ARCH" = "arm64" ]; then
    BINARY_PATH="build/Output/macos/arm64/rmmagent"
    ARCH_DESC="Apple Silicon ARM64"
elif [ "$ARCH" = "universal" ]; then
    BINARY_PATH="build/Output/macos/universal/rmmagent"
    ARCH_DESC="Universal (Intel + ARM)"
fi

#==============================================================================
# CONFIGURATION DISPLAY
#==============================================================================

echo "=========================================="
echo "rmmagent Build Configuration v2"
echo "=========================================="
echo "Start Time:       $(date '+%Y-%m-%d %H:%M:%S')"
echo "Architecture:     $ARCH_DESC"
echo "Skip Build:       $SKIP_BUILD"
echo "Skip Sign:        $SKIP_SIGN"
echo "Skip Notary:      $SKIP_NOTARY"
echo "Skip Git Pull:    $SKIP_GIT_PULL"
echo "Deploy Build:     $DEPLOY_BUILD"
echo ""
if [ "$TRMM_EXEC" = "yes" ] && [ -n "$TRMM_MODE" ]; then
    echo "Execute TRMM:     yes"
    echo "Mode:             -m $TRMM_MODE"
    [ -n "$TRMM_API" ] && echo "API:              --api $TRMM_API"
    [ -n "$TRMM_CLIENT" ] && echo "Client ID:        --client-id $TRMM_CLIENT"
    [ -n "$TRMM_SITE" ] && echo "Site ID:          --site-id $TRMM_SITE"
    [ -n "$TRMM_AGENT" ] && echo "Agent Type:       --agent-type $TRMM_AGENT"
    [ -n "$TRMM_AUTH" ] && echo "Auth Token:       --auth ${TRMM_AUTH:0:20}..."
else
    echo "Execute TRMM:     no (build only)"
fi
echo "=========================================="
echo ""

#==============================================================================
# GIT PULL STEP
#==============================================================================

if [ "$SKIP_GIT_PULL" = "no" ]; then
    echo "[0/4] Updating repository..."
    echo "[$(date '+%H:%M:%S')] Git pull started"
    # Run git pull as the actual user (not root)
    sudo -u $SUDO_USER git pull
    echo "[$(date '+%H:%M:%S')] Git pull complete"
    echo "✓ Repository updated"
    echo ""
else
    echo "[0/4] Git pull - SKIPPED"
    echo ""
fi

#==============================================================================
# BUILD STEP
#==============================================================================

if [ "$SKIP_BUILD" = "no" ]; then
    echo "[1/4] Building rmmagent ($ARCH_DESC)..."
    echo "[$(date '+%H:%M:%S')] Build started"

    # Run build as the actual user (not root)
    if [ "$ARCH" = "universal" ]; then
        echo "  Building for multiple architectures..."

        # Define output paths
        AMD64_OUTPUT="$REPO_DIR/build/Output/macos/amd64"
        ARM64_OUTPUT="$REPO_DIR/build/Output/macos/arm64"
        UNIVERSAL_OUTPUT="$REPO_DIR/build/Output/macos/universal"

        # Create output directories
        mkdir -p "$AMD64_OUTPUT"
        mkdir -p "$ARM64_OUTPUT"
        mkdir -p "$UNIVERSAL_OUTPUT"

        # Build AMD64
        echo "  Building AMD64 binary (targeting macOS 10.15+)..."
        sudo -u $SUDO_USER bash -c "cd '$REPO_DIR' && CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 MACOSX_DEPLOYMENT_TARGET=10.15 go build -o '$AMD64_OUTPUT/rmmagent' -ldflags='-s -w' ."
        echo "  ✓ AMD64 build complete"

        # Build ARM64
        echo "  Building ARM64 binary (targeting macOS 11.0+)..."
        sudo -u $SUDO_USER bash -c "cd '$REPO_DIR' && CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 MACOSX_DEPLOYMENT_TARGET=11.0 go build -o '$ARM64_OUTPUT/rmmagent' -ldflags='-s -w -linkmode=external' ."
        echo "  ✓ ARM64 build complete"

        # Create universal binary with lipo
        echo "  Creating universal binary with lipo..."
        lipo -create \
            "$AMD64_OUTPUT/rmmagent" \
            "$ARM64_OUTPUT/rmmagent" \
            -output "$UNIVERSAL_OUTPUT/rmmagent"
        echo "  ✓ Universal binary created"

        # Verify the universal binary
        echo "  Verifying architectures:"
        lipo -info "$UNIVERSAL_OUTPUT/rmmagent" | sed 's/^/    /'

        # Show file sizes
        echo "  Binary sizes:"
        ls -lh "$AMD64_OUTPUT/rmmagent" | awk '{print "    AMD64:     " $5}'
        ls -lh "$ARM64_OUTPUT/rmmagent" | awk '{print "    ARM64:     " $5}'
        ls -lh "$UNIVERSAL_OUTPUT/rmmagent" | awk '{print "    Universal: " $5}'
    else
        # Build single architecture
        # Set deployment target based on architecture
        if [ "$ARCH" = "arm64" ]; then
            DEPLOYMENT_TARGET="11.0"
            LDFLAGS="-s -w -linkmode=external"
            echo "  Building $ARCH binary (targeting macOS 11.0+)..."
        else
            DEPLOYMENT_TARGET="10.15"
            LDFLAGS="-s -w"
            echo "  Building $ARCH binary (targeting macOS 10.15+)..."
        fi
        sudo -u $SUDO_USER bash -c "cd '$REPO_DIR' && CGO_ENABLED=1 GOOS=darwin GOARCH=$ARCH MACOSX_DEPLOYMENT_TARGET=$DEPLOYMENT_TARGET go build -o '$BINARY_PATH' -ldflags='$LDFLAGS' ."
        echo "  ✓ $ARCH build complete"

        # Show file size
        echo "  Binary size:"
        ls -lh "$BINARY_PATH" | awk '{print "    " $5}'
    fi

    echo "[$(date '+%H:%M:%S')] Build complete"
    echo "✓ Build complete"
    echo ""
else
    echo "[1/4] Build - SKIPPED"

    # If TRMM_EXEC is set and build is skipped, verify binary exists
    if [ "$TRMM_EXEC" = "yes" ] && [ -n "$TRMM_MODE" ]; then
        if [ ! -f "$BINARY_PATH" ]; then
            echo ""
            echo "ERROR: Binary not found at $BINARY_PATH"
            echo "Cannot run command '$TRMM_MODE' without a binary."
            echo ""
            echo "Solutions:"
            echo "  1. Remove --skip-build to build the binary"
            echo "  2. Build the binary first"
            echo "  3. Ensure the binary exists at: $BINARY_PATH"
            exit 1
        fi
        echo "  ✓ Binary exists at $BINARY_PATH"
    fi
    echo ""
fi

#==============================================================================
# SIGNING STEP
#==============================================================================

if [ "$SKIP_SIGN" = "no" ]; then
    echo "[2/4] Signing binary..."
    echo "[$(date '+%H:%M:%S')] Signing started"
    # Run signing as the actual user (not root) to access user's keychain
    # Pass the specific binary path to sign and preserve MACOS_SIGN_CERT
    sudo -u $SUDO_USER MACOS_SIGN_CERT="$MACOS_SIGN_CERT" ./bin/macos_build/macos-sign.sh "$BINARY_PATH"
    echo "[$(date '+%H:%M:%S')] Signing complete"
    echo "✓ Signing complete"
    echo ""
else
    echo "[2/4] Signing - SKIPPED"
    echo ""
fi

#==============================================================================
# NOTARIZATION STEP
#==============================================================================

if [ "$SKIP_NOTARY" = "no" ]; then
    echo "[3/4] Notarizing binary..."
    echo "[$(date '+%H:%M:%S')] Notarization started"
    # Run notarization as the actual user (not root) to access user's keychain
    # Pass the specific binary path to notarize
    sudo -u $SUDO_USER ./bin/macos_build/macos-notarize.sh "$BINARY_PATH"
    echo "[$(date '+%H:%M:%S')] Notarization complete"
    echo "✓ Notarization complete"
    echo ""
else
    echo "[3/4] Notarization - SKIPPED"
    echo ""
fi

#==============================================================================
# DEPLOYMENT STEP
#==============================================================================

if [ "$DEPLOY_BUILD" = "yes" ]; then
    echo "[4/5] Deploying to /opt/tacticalagent/..."
    echo "[$(date '+%H:%M:%S')] Deployment started"

    DEPLOY_PATH="/opt/tacticalagent/tacticalagent"
    PLIST_PATH="/Library/LaunchDaemons/tacticalagent.plist"
    PLIST_LABEL="tacticalagent"

    # Check if LaunchDaemon exists
    if [ -f "$PLIST_PATH" ]; then
        echo "  ✓ Found LaunchDaemon at $PLIST_PATH"

        # Check if service is loaded
        if launchctl list | grep -q "$PLIST_LABEL"; then
            echo "  Unloading LaunchDaemon..."
            launchctl bootout system "$PLIST_PATH" 2>/dev/null || true
            echo "  ✓ LaunchDaemon unloaded"
        else
            echo "  LaunchDaemon not currently loaded"
        fi
    else
        echo "  LaunchDaemon not found at $PLIST_PATH (first-time deployment)"
    fi

    # Ensure destination directory exists
    if [ ! -d "/opt/tacticalagent" ]; then
        echo "  Creating /opt/tacticalagent directory..."
        mkdir -p /opt/tacticalagent
        echo "  ✓ Directory created"
    fi

    # Delete existing binary if present
    if [ -f "$DEPLOY_PATH" ]; then
        echo "  Removing existing binary at $DEPLOY_PATH..."
        rm -f "$DEPLOY_PATH"
        echo "  ✓ Existing binary removed"
    fi

    # Copy binary to deployment location using ditto
    echo "  Copying binary to $DEPLOY_PATH with ditto..."
    ditto "$BINARY_PATH" "$DEPLOY_PATH"
    chmod 755 "$DEPLOY_PATH"
    echo "  ✓ Binary copied and permissions set"

    # Reload LaunchDaemon if it exists
    if [ -f "$PLIST_PATH" ]; then
        echo "  Reloading LaunchDaemon..."
        launchctl bootstrap system "$PLIST_PATH" 2>/dev/null || true

        # Wait a moment for service to start
        sleep 2

        # Verify service loaded
        if launchctl list | grep -q "$PLIST_LABEL"; then
            echo "  ✓ LaunchDaemon reloaded and running"
        else
            echo "  ⚠ LaunchDaemon loaded but may not be running (check logs)"
        fi
    else
        echo "  ⚠ No LaunchDaemon to reload (binary deployed but service not configured)"
    fi

    echo "[$(date '+%H:%M:%S')] Deployment complete"
    echo "✓ Deployment complete"
    echo ""
else
    echo "[4/5] Deployment - SKIPPED"
    echo ""
fi

#==============================================================================
# COMMAND EXECUTION
#==============================================================================

if [ "$TRMM_EXEC" = "yes" ] && [ -n "$TRMM_MODE" ]; then
    echo "[5/5] Executing Tactical RMM agent..."
    echo "[$(date '+%H:%M:%S')] Command execution started"
    echo "  Mode: -m $TRMM_MODE"
    echo "  Binary: $BINARY_PATH"

    # Build command array - only include parameters that were explicitly set
    CMD_ARRAY=("$BINARY_PATH" "-m" "$TRMM_MODE")

    # Add API parameter if set
    if [ -n "$TRMM_API" ]; then
        CMD_ARRAY+=("--api" "$TRMM_API")
        echo "  API: $TRMM_API"
    fi

    # Add Client ID if set
    if [ -n "$TRMM_CLIENT" ]; then
        CMD_ARRAY+=("--client-id" "$TRMM_CLIENT")
        echo "  Client ID: $TRMM_CLIENT"
    fi

    # Add Site ID if set
    if [ -n "$TRMM_SITE" ]; then
        CMD_ARRAY+=("--site-id" "$TRMM_SITE")
        echo "  Site ID: $TRMM_SITE"
    fi

    # Add Agent Type if set
    if [ -n "$TRMM_AGENT" ]; then
        CMD_ARRAY+=("--agent-type" "$TRMM_AGENT")
        echo "  Agent Type: $TRMM_AGENT"
    fi

    # Add Auth Token if set
    if [ -n "$TRMM_AUTH" ]; then
        CMD_ARRAY+=("--auth" "$TRMM_AUTH")
        echo "  Auth Token: ${TRMM_AUTH:0:20}..."
    fi

    echo ""
    echo "Running command:"
    printf '  %s ' "${CMD_ARRAY[@]}"
    echo ""
    echo ""

    # Execute tactical RMM agent command
    "${CMD_ARRAY[@]}"

    echo ""
    echo "[$(date '+%H:%M:%S')] Command execution complete"
    echo "✓ Command executed successfully"
    echo ""
else
    echo "[5/5] Command execution - SKIPPED (TRMM_EXEC=no or no mode specified)"
    echo ""
fi

#==============================================================================
# SUMMARY
#==============================================================================

echo "=========================================="
echo "Script Complete!"
echo "=========================================="
echo "Architecture:     $ARCH_DESC"
echo "Binary:           $BINARY_PATH"

if [ "$TRMM_EXEC" = "yes" ] && [ -n "$TRMM_MODE" ]; then
    echo "TRMM Mode:        -m $TRMM_MODE"
    [ -n "$TRMM_API" ] && echo "TRMM API:         $TRMM_API"
    echo ""
    echo "Agent execution complete"
else
    echo "TRMM Execution:   (none - binary built only)"
    echo ""
    echo "Binary available at: $BINARY_PATH"
    echo "To execute TRMM installation, run with --trmm-mode option"
fi
echo ""
echo "=========================================="
echo "End Time:         $(date '+%Y-%m-%d %H:%M:%S')"
echo "=========================================="
echo ""
echo "Press Enter to open build folder (or any other key to exit)..."

# Wait for user input with 15-second timeout
if read -t 15 -n 1 -s key; then
    # User pressed a key before timeout
    if [ -z "$key" ]; then
        # Enter key was pressed (empty string)
        OUTPUT_DIR="$(cd "$(dirname "$BINARY_PATH")" && pwd)"
        echo ""
        echo "Opening $OUTPUT_DIR..."
        open "$OUTPUT_DIR"
    fi
else
    # Timeout occurred (15 seconds elapsed with no input)
    echo ""
fi
