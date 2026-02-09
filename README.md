# Branch Migration Guide

## ⚠️ Important Notice

The `main` branch is **no longer the default branch** and is **no longer actively maintained**. This repository has migrated to a new default branch structure.

---

## Migrating to the New Default Branch (`chipsec2`)

If you have a local repository pointing to the old `main` branch, follow these steps to update:

### If your remote is `origin` (default)

#### 1. Fetch the latest branch information
```bash
git fetch origin
```

#### 2. Switch to the new default branch
```bash
git checkout chipsec2
```

#### 3. Update your local tracking branch (optional but recommended)
```bash
git branch -u origin/chipsec2
```

#### 4. Update your remote HEAD reference (if cloning fresh)
```bash
git remote set-head origin --auto
```

### If your remote is `upstream` (forked repository)

If you're working with a forked repository where `origin` points to your fork and `upstream` points to the main chipsec repository, use these commands instead:

#### 1. Fetch the latest branch information from upstream
```bash
git fetch upstream
```

#### 2. Switch to the new default branch
```bash
git checkout chipsec2
```

#### 3. Update your local tracking branch (optional but recommended)
```bash
git branch -u upstream/chipsec2
```

#### 4. Update your remote HEAD reference (if cloning fresh)
```bash
git remote set-head upstream --auto
```

#### 5. Keep your fork synchronized
```bash
git push origin chipsec2
```

---

## Legacy Support (`chipsec1` branch)

If you require support for **older Intel platforms**, use the `chipsec1` branch:

- **Client Platforms:** Pre-ADL (pre-12th Gen Core)
- **Server Platforms:** Pre-SPR (pre-3rd Gen Xeon Scalable)

To switch to the legacy branch:
```bash
git checkout chipsec1
```

---

## Summary of Branches

| Branch | Status | Use Case |
|--------|--------|----------|
| `chipsec2` | ✅ **Active (Default)** | Current development, ADL and newer platforms |
| `chipsec1` | ⚠️ Legacy Support | Pre-ADL client and pre-SPR server platforms, not activly maintined (only urgent changes.) |
| `main` | ❌ Deprecated | No longer maintained; do not use |

---

## Need Help?

For more information on platform support and updates, please refer to the main repository documentation or contact chipsec@intel.com
