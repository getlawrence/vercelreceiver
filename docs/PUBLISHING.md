# Publishing Guide

This document explains how to publish the Vercel Receiver Go module to pkg.go.dev.

## Overview

The repository includes automated GitHub Actions workflows that handle the complete publishing process when you create a release tag. The module will be automatically published to [pkg.go.dev](https://pkg.go.dev) and become available for other developers to use.

## Publishing Methods

### Method 1: Automatic Publishing (Recommended)

The easiest way to publish is to create a Git tag, which automatically triggers the publishing workflow:

1. **Ensure your code is ready:**
   ```bash
   # Run tests to ensure everything works
   go test ./...
   
   # Run integration tests
   go test -tags=integration ./...
   
   # Clean up dependencies
   go mod tidy
   ```

2. **Create and push a release tag:**
   ```bash
   # Create a new version tag (following semantic versioning)
   git tag -a v1.0.0 -m "Release v1.0.0"
   
   # Push the tag to trigger the publishing workflow
   git push origin v1.0.0
   ```

3. **Monitor the workflow:**
   - Check the [GitHub Actions](https://github.com/getlawrence/vercelreceiver/actions) tab
   - The workflow will automatically:
     - Run all tests
     - Create a GitHub release with binaries
     - Publish the module to pkg.go.dev
     - Verify the publication

### Method 2: Manual Publishing

You can also manually trigger the publishing workflow:

1. Go to the [Publish Module workflow](https://github.com/getlawrence/vercelreceiver/actions/workflows/publish-module.yml)
2. Click "Run workflow"
3. Enter the version tag (e.g., `v1.0.0`)
4. Optionally enable "Force" to republish an existing version
5. Click "Run workflow"

### Method 3: Using the Test Script

For convenience, use the provided test script:

```bash
# Make sure you're on the main branch with no uncommitted changes
./scripts/publish-test.sh
```

The script will:
- Check for uncommitted changes
- Suggest the next version number
- Run tests before publishing
- Create and push the tag
- Provide links to monitor the process

## Version Numbering

Follow [semantic versioning](https://semver.org/) for your releases:

- **v1.0.0** - Major release (breaking changes)
- **v1.1.0** - Minor release (new features, backward compatible)
- **v1.1.1** - Patch release (bug fixes, backward compatible)
- **v1.0.0-beta** - Pre-release versions

## What Happens During Publishing

The automated workflow performs these steps:

1. **Validation:**
   - Verifies tag format follows semantic versioning
   - Checks if version is already published (unless forced)
   - Ensures tag exists in repository

2. **Testing:**
   - Runs unit tests with race detection
   - Runs integration tests
   - Verifies module dependencies

3. **Publishing:**
   - Tidies module dependencies
   - Triggers pkg.go.dev indexing
   - Waits for publication confirmation

4. **Verification:**
   - Confirms module is accessible
   - Provides direct links to documentation

## After Publishing

Once published, your module will be available at:

- **Module URL:** https://pkg.go.dev/github.com/getlawrence/vercelreceiver@v1.0.0
- **Documentation:** https://pkg.go.dev/github.com/getlawrence/vercelreceiver@v1.0.0

Users can install your module with:

```bash
go get github.com/getlawrence/vercelreceiver@v1.0.0
```

## Troubleshooting

### Module Not Appearing on pkg.go.dev

- **Wait a few minutes:** Indexing can take 5-10 minutes
- **Check the workflow logs:** Look for any errors in the GitHub Actions
- **Verify tag format:** Ensure it follows `v1.2.3` format
- **Check repository permissions:** Ensure the repository is public

### Already Published Error

If you get an "already published" error:

- **Use force mode:** Enable the "Force" option in manual workflow runs
- **Check existing versions:** Verify the version isn't already published
- **Increment version:** Create a new version number

### Test Failures

If tests fail during publishing:

- **Fix locally first:** Run `go test ./...` and fix any issues
- **Check integration tests:** Run `go test -tags=integration ./...`
- **Verify dependencies:** Run `go mod tidy` and `go mod verify`

## Best Practices

1. **Always test before publishing:**
   ```bash
   go test ./...
   go test -tags=integration ./...
   ```

2. **Use meaningful commit messages:**
   ```bash
   git commit -m "feat: add support for custom headers"
   git tag -a v1.1.0 -m "Release v1.1.0: Add custom header support"
   ```

3. **Keep releases focused:**
   - One feature or bug fix per release
   - Clear, descriptive release notes

4. **Monitor the workflow:**
   - Check GitHub Actions for any failures
   - Verify the module appears on pkg.go.dev

## Security Notes

- **Never change published versions:** Once published, a version is immutable
- **Use semantic versioning:** Helps users understand the impact of updates
- **Test thoroughly:** Ensure quality before publishing

## Related Links

- [Go Module Publishing Documentation](https://go.dev/doc/modules/publishing)
- [Semantic Versioning](https://semver.org/)
- [pkg.go.dev](https://pkg.go.dev)
- [GitHub Actions](https://github.com/getlawrence/vercelreceiver/actions)
