#!/bin/bash
set -e

# Check for uncommitted changes first
if ! git diff-index --quiet HEAD --; then
    echo "Error: You have uncommitted changes. Please commit or stash them first."
    exit 1
fi

# Fetch latest remote state and pull changes
echo "Pulling latest changes from remote..."
git pull origin main

# Default to patch release
RELEASE_TYPE=${1:-patch}

# Validate release type
case $RELEASE_TYPE in
major | minor | patch) ;;
*)
    echo "Usage: $0 [major|minor|patch]"
    echo "Examples:"
    echo "  $0 patch    # 1.0.0 -> 1.0.1"
    echo "  $0 minor    # 1.0.0 -> 1.1.0"
    echo "  $0 major    # 1.0.0 -> 2.0.0"
    exit 1
    ;;
esac

# Bump version using uv
echo "Bumping version..."
NEW_VERSION=$(uv version --short --bump "$RELEASE_TYPE" 2>/dev/null)

echo "New version: $NEW_VERSION"

read -p "Create release $NEW_VERSION? [y/N] " -r
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Committing version bump..."
    git add pyproject.toml uv.lock
    git commit -m "Bump version to $NEW_VERSION"

    echo "Pushing version bump to origin..."
    git push origin main

    echo "Creating annotated tag..."
    git tag -a "$NEW_VERSION" -m "Release $NEW_VERSION"

    echo "Pushing tag to origin..."
    git push origin "$NEW_VERSION"

    echo "Release $NEW_VERSION created successfully!"
    echo "Binary build will start automatically via GitHub Actions."
    echo "Monitor at https://github.com/Ch00k/claude-journal/actions"
else
    echo "Release cancelled"
    echo "Reverting version bump..."
    git restore pyproject.toml uv.lock
fi
