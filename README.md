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

## Resources

- [Minimal Mistakes Documentation](https://mmistakes.github.io/minimal-mistakes/docs/quick-start-guide/)
- [Jekyll Documentation](https://jekyllrb.com/docs/)
- [GitHub Pages Documentation](https://docs.github.com/en/pages)
