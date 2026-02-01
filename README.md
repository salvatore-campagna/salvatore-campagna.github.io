# Salvatore Campagna's Blog

Personal blog about software engineering, JVM performance, systems programming, and search engines.

Built with [Jekyll](https://jekyllrb.com/) and the [Minimal Mistakes](https://mmistakes.github.io/minimal-mistakes/) theme, hosted on [GitHub Pages](https://pages.github.com/).

## Quick Start

### Option 1: Just Push to GitHub (Easiest)

1. Create a new repository named `yourusername.github.io`
2. Push this directory to that repo:
   ```bash
   cd ~/workspace/blog
   git init
   git add .
   git commit -m "Initial blog setup"
   git remote add origin https://github.com/yourusername/yourusername.github.io.git
   git push -u origin main
   ```
3. Go to repo Settings → Pages → Enable from `main` branch
4. Wait 1-2 minutes, then visit `https://yourusername.github.io`

GitHub will build the site automatically using Jekyll.

### Option 2: Local Development

If you want to preview locally before pushing:

```bash
# Install Ruby (if not already installed)
brew install ruby

# Add Ruby to PATH (add to ~/.zshrc)
export PATH="/opt/homebrew/opt/ruby/bin:$PATH"

# Install bundler and Jekyll
gem install bundler jekyll

# Install dependencies
cd ~/workspace/blog
bundle install

# Run local server
bundle exec jekyll serve

# Visit http://localhost:4000
```

## Writing Posts

Create a new file in `_posts/` with the format:

```
_posts/YYYY-MM-DD-title-of-post.md
```

Example front matter:

```yaml
---
title: "Your Post Title"
excerpt: "A short description for previews"
date: 2026-01-18
categories:
  - Java
  - Performance
tags:
  - jvm
  - profiling
toc: true
---

Your content here...
```

## Customization

### Change Theme Skin

Edit `_config.yml`:
```yaml
minimal_mistakes_skin: "dark"  # Options: air, aqua, contrast, dark, dirt, neon, mint, plum, sunrise
```

### Add Social Links

Edit the `author.links` section in `_config.yml`.

### Add Navigation

Create `_data/navigation.yml`:
```yaml
main:
  - title: "Posts"
    url: /
  - title: "About"
    url: /about/
  - title: "Tags"
    url: /tags/
```

## GitHub Account

This blog is published under the **salvatore-campagna** GitHub account at `salvatore-campagna.github.io`.

Set the correct git user for this repo:

```bash
cd ~/workspace/blog
git config user.name "Salvatore Campagna"
git config user.email "your-personal-email@example.com"
```

If you have multiple GitHub accounts configured with `gh`, switch between them:

```bash
# Check which account is active
gh auth status

# Switch to the blog account
gh auth switch -u salvatore-campagna

# Switch to the other account
gh auth switch -u salvatorecampagna
```

## Directory Structure

```
blog/
├── _config.yml          # Site configuration
├── _posts/              # Blog posts (YYYY-MM-DD-title.md)
├── _pages/              # Static pages (about, etc.)
├── assets/
│   └── images/          # Images for posts
├── index.html           # Home page
└── README.md            # This file
```

## Enabling Comments with Giscus

This blog uses [Giscus](https://giscus.app/) for comments. Giscus is a lightweight, open-source commenting system that stores all comments as **GitHub Discussions** on your repository — no external database or third-party account needed. Readers comment using their GitHub account, and every comment thread is visible both on the blog and in the repository's Discussions tab.

### Prerequisites

- A **public** GitHub repository (Giscus cannot access private repos)
- GitHub Discussions enabled on the repository
- The [Giscus GitHub App](https://github.com/apps/giscus) installed on the repository

### Setup Steps

#### Step 1: Enable GitHub Discussions

1. Go to your repository on GitHub: [salvatore-campagna/salvatore-campagna.github.io](https://github.com/salvatore-campagna/salvatore-campagna.github.io)
2. Click **Settings** → **General**
3. Scroll down to the **Features** section
4. Check the **Discussions** checkbox and save

> This can also be done via the GitHub CLI:
> ```bash
> gh api repos/salvatore-campagna/salvatore-campagna.github.io -X PATCH -f has_discussions=true
> ```

#### Step 2: Install the Giscus GitHub App

1. Visit [https://github.com/apps/giscus](https://github.com/apps/giscus)
2. Click **Install**
3. Choose **Only select repositories** and pick `salvatore-campagna.github.io`
4. Click **Install**

This grants Giscus permission to read and create Discussions on your repo. It does **not** get access to your code.

#### Step 3: Get your `repo_id` and `category_id`

If you ever need to reconfigure these values:

1. Visit [https://giscus.app/](https://giscus.app/)
2. In the **Repository** field, enter: `salvatore-campagna/salvatore-campagna.github.io`
3. Under **Discussion Category**, select **Announcements**
4. Scroll down to the generated `<script>` tag and copy the values of:
   - `data-repo-id` → this is your `repo_id`
   - `data-category-id` → this is your `category_id`

> You can also retrieve these via the GitHub GraphQL API:
> ```bash
> gh api graphql -f query='{
>   repository(owner: "salvatore-campagna", name: "salvatore-campagna.github.io") {
>     id
>     discussionCategories(first: 10) {
>       nodes { id name }
>     }
>   }
> }'
> ```

#### Step 4: Update `_config.yml`

The giscus section in `_config.yml` should look like this (already configured):

```yaml
comments:
  active: giscus
  giscus:
    repo: salvatore-campagna/salvatore-campagna.github.io
    repo_id: R_kgDOQ8OMWw
    category: Announcements
    category_id: DIC_kwDOQ8OMW84C1ux9
    mapping: pathname
    strict: 0
    input_position: bottom
    lang: en
    reactions_enabled: 1
```

| Setting | Purpose |
|---------|---------|
| `mapping: pathname` | Each post's URL path maps to a unique Discussion thread |
| `strict: 0` | Allows fuzzy matching of pathnames (tolerates trailing slashes, etc.) |
| `input_position: bottom` | Comment box appears below existing comments |
| `reactions_enabled: 1` | Enables emoji reactions on the main post |

#### Step 5: Verify post defaults

Posts must have `comments: true` in their front matter. This is already set globally in the defaults section of `_config.yml`, so all posts get comments automatically. To disable comments on a specific post, add `comments: false` to that post's front matter.

### How It Works

- When a reader opens a blog post, the Giscus widget loads in an `<iframe>`
- On first comment, Giscus automatically creates a Discussion in the **Announcements** category
- The Discussion title matches the post's URL pathname
- All subsequent comments on that post appear in the same Discussion
- Comments are visible both on the blog and in the repo's [Discussions tab](https://github.com/salvatore-campagna/salvatore-campagna.github.io/discussions)

### Troubleshooting

| Problem | Solution |
|---------|----------|
| Comment widget doesn't appear | Verify the Giscus app is installed and the repo is public |
| "Discussion not found" error | Check that `repo_id` and `category_id` are correct |
| Comments disabled on a post | Check the post's front matter for `comments: false` |
| Widget loads but can't create discussions | Ensure the Announcements category exists in Discussions |

## Resources

- [Minimal Mistakes Documentation](https://mmistakes.github.io/minimal-mistakes/docs/quick-start-guide/)
- [Jekyll Documentation](https://jekyllrb.com/docs/)
- [GitHub Pages Documentation](https://docs.github.com/en/pages)
