# RPISEC Site / Blog

I'll use Ruby and you can't stop me.

## Howto

### Install Ruby
```
sudo apt-get update
sudo apt-get install ruby-full ruby-bundle
```

This project does not yet support Ruby >= 3.0.0. Use the following steps to install a usable version.

```
git clone https://github.com/rbenv/rbenv.git ~/.rbenv
git clone https://github.com/rbenv/ruby-build.git ~/.rbenv/plugins/ruby-build

echo 'export PATH="$HOME/.rbenv/bin:$PATH"' >> ~/.bashrc
echo 'eval "$(rbenv init -)"' >> ~/.bashrc

source ~/.bashrc

rbenv install 2.7.8

# run while in the website/ directory
rbenv local 2.7.8
```


### Install dependencies

```
bundle install
```

### Build site locally

This will build the site and bind a web server to `localhost:4000`:

```
bundle exec jekyll serve
```

### Add new blog post

Add new a new markdown file to `_posts/`

### Publish changes

Commit and push to the repo, GitHub Pages will build the site automagically^tm.
