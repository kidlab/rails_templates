# Rails application template for API app.
# Inspired by http://railswizard.org

# >----------------------------[ Initial Setup ]------------------------------<

initializer 'generators.rb', <<-RUBY
Rails.application.config.generators do |g|
end
RUBY

@recipes = [
  # Database
  "activerecord",
  # Security
  "devise",
  "cancan",
  # Template engine
  "haml",
  # Json engine
  "oj",
  # Decorator
  "draper",
  # Controller helper
  "decent_exposure",
  # Attachment
  "paperclip",
  # Setting file
  "settingslogic",
  # Soft delete
  "paranoia",
  # Pagination
  "kaminari",
  # Caching
  "dalli",
  # Admin
  "rails_admin",
  # Performance monitor
  "newrelic_rpm",
  # Test
  "rspec",
  "simplecov",
  "factory_girl_rails",
  # Development and test utilities
  "annotate",
  "pry-rails",
  "byebug",
  "better_errors",
  "quiet_assets",
  "html2haml",
  "faker",
  "spring",
  # Web server
  "unicorn",
  "thin",
  # Source control
  "git"
]

def recipes
  @recipes
end

def recipe?(name)
  @recipes.include?(name)
end

def say_custom(tag, text)
  say "\033[1m\033[36m" + tag.to_s.rjust(10) + "\033[0m" + "  #{text}"
end

def say_recipe(name)
  say "\033[1m\033[36m" + "recipe".rjust(10) + "\033[0m" + "  Running #{name} recipe..."
end

def say_wizard(text)
  say_custom(@current_recipe || 'wizard', text)
end

@current_recipe = nil
@configs = {}

@after_blocks = []
def after_bundler(&block)
  @after_blocks << [@current_recipe, block]
end

@after_everything_blocks = []
def after_everything(&block)
  @after_everything_blocks << [@current_recipe, block]
end

@before_configs = {}
def before_config(&block)
  @before_configs[@current_recipe] = block
end

def gemfile_comment(comment)
  append_to_file 'Gemfile' do
    "\n# #{comment}"
  end
end

# >-----------------------------[ ActiveRecord ]------------------------------<

@current_recipe = "activerecord"
@before_configs["activerecord"].call if @before_configs["activerecord"]
say_recipe 'ActiveRecord'

config = {}
config['database'] = 'postgresql'
@configs[@current_recipe] = config

if config['database']
  say_wizard "Configuring '#{config['database']}' database settings..."
  old_gem = gem_for_database
  @options = @options.dup.merge(database: config['database'])
  gsub_file 'Gemfile', "gem '#{old_gem}'", "gem '#{gem_for_database}'"
  template "config/databases/#{@options[:database]}.yml", "config/database.yml.new"
  run 'mv config/database.yml.new config/database.yml'
end

# >--------------------------------[ Devise ]---------------------------------<

gemfile_comment "Authentication"

@current_recipe = "devise"
@before_configs["devise"].call if @before_configs["devise"]
say_recipe 'Devise'

@configs[@current_recipe] = config

gem 'devise'

after_bundler do
  generate 'devise:install'
  generate 'devise AdminUser'
  generate 'devise User'
end

# >--------------------------------[ Cancan ]---------------------------------<

gemfile_comment "Authorization"

@current_recipe = "cancan"
@before_configs["cancan"].call if @before_configs["cancan"]
say_recipe 'Cancan'

@configs[@current_recipe] = config

gem 'cancan'

after_bundler do
  generate 'cancan:ability'
end

# >---------------------------------[ HAML ]----------------------------------<

gemfile_comment "Template engine"

@current_recipe = "haml"
@before_configs["haml"].call if @before_configs["haml"]
say_recipe 'HAML'

@configs[@current_recipe] = config

gem 'haml', '>= 4.0.5'
gem 'haml-rails'

# >---------------------------------[ OJ ]----------------------------------<

gemfile_comment "JSON engine"

@current_recipe = "oj"
@before_configs["oj"].call if @before_configs["oj"]
say_recipe 'OJ'

@configs[@current_recipe] = config

gem 'oj'
gem 'oj_mimic_json'

# >---------------------------------[ Draper ]----------------------------------<

gemfile_comment "Decorator"

@current_recipe = "draper"
@before_configs["draper"].call if @before_configs["draper"]
say_recipe 'Draper'

@configs[@current_recipe] = config

gem 'draper', github: 'drapergem/draper'

after_bundler do
  FileUtils.mkdir 'app/decorators'
  FileUtils.touch 'app/decorators/.keep'
end

# >---------------------------------[ Decent exposure ]----------------------------------<

gemfile_comment "Controller helper"

@current_recipe = "decent_exposure"
@before_configs["decent_exposure"].call if @before_configs["decent_exposure"]
say_recipe 'Decent exposure'

@configs[@current_recipe] = config

gem 'decent_exposure'

# >---------------------------------[ Paperclip ]----------------------------------<

gemfile_comment "Attached files"

@current_recipe = "paperclip"
@before_configs["paperclip"].call if @before_configs["paperclip"]
say_recipe 'Paperclip'

@configs[@current_recipe] = config

gem 'paperclip'
gem 'aws-sdk'

after_bundler do
  # Add paperclip config to environment files.
  inject_into_file "config/environments/development.rb", before: /^end/ do
%q{
  # The dev configuration for Paperclip that stores images locally
  config.paperclip_defaults = {
    path: ":rails_root/public/photos/:id/:style.:extension",
    url: "/photos/:id/:style.:extension"
  }

}
  end

  inject_into_file "config/environments/test.rb", before: /^end/ do
%q{
  # Return fake URL.
  config.paperclip_defaults = {
    url: "#{Settings.cdn.paths.photos}/:id/:style.:extension"
  }

}
  end

  inject_into_file "config/environments/production.rb", before: /^end/ do
%q{
  config.paperclip_defaults = {
    storage: :s3,
    s3_credentials: {
      bucket: Settings.aws.s3.bucket,
      access_key_id: Settings.aws.s3.access_key_id,
      secret_access_key: Settings.aws.s3.secret_access_key,
      s3_host_name: Settings.aws.s3.host_name
    },
    url: ":s3_domain_url",
    path: "photos/:id/:style.jpg"
  }

}
  end
end

# >---------------------------------[ SettingsLogic ]----------------------------------<

gemfile_comment "Setting file"

@current_recipe = "settingslogic"
@before_configs["settingslogic"].call if @before_configs["settingslogic"]
say_recipe 'SettingsLogic'

@configs[@current_recipe] = config

gem 'settingslogic'

after_bundler do
  create_file 'config/settings.yml' do
<<-SETTINGS
defaults: &defaults
  host: 'http://localhost:3000'
  email: &email
    default_from: 'noreply@please-change-me.com'
  aws:
    s3:
      bucket: "DEV_BUCKET"
      access_key_id: "access_id"
      secret_access_key: "secret"
      host_name: "s3-ap-southeast-1.amazonaws.com"

development:
  <<: *defaults

test:
  <<: *defaults

staging:
  <<: *defaults
  host: 'http://staging.server.com'
  aws:
    s3:
      bucket: "STAGING_BUCKET"
      access_key_id: "access_id"
      secret_access_key: "secret"
      host_name: "s3-ap-southeast-1.amazonaws.com"

production:
  <<: *defaults
  host: 'http://server.com'
  aws:
    s3:
      bucket: "PROD_BUCKET"
      access_key_id: "access_id"
      secret_access_key: "secret"
      host_name: "s3-ap-southeast-1.amazonaws.com"

SETTINGS
  end

  create_file 'lib/settings.rb' do
%q{
class Settings < Settingslogic
  source "#{Rails.root}/config/api-keys.yml"
  namespace Rails.env
end

}
  end

  inject_into_file 'config/application.rb', after: "class Application < Rails::Application\n" do
%q{
    config.autoload_paths += %W(#{config.root}/lib)
    require 'settings'

}
  end
end

# >---------------------------------[ Paranoia ]----------------------------------<

gemfile_comment "Soft delete"

@current_recipe = "paranoia"
@before_configs["paranoia"].call if @before_configs["paranoia"]
say_recipe 'Paranoia'

@configs[@current_recipe] = config

gem 'paranoia'
gem 'paranoia_uniqueness_validator'

# >---------------------------------[ Kaminari ]----------------------------------<

@current_recipe = "kaminari"
@before_configs["kaminari"].call if @before_configs["kaminari"]
say_recipe 'Kaminari'

gemfile_comment "Pagination"

gem 'kaminari'

# >---------------------------------[ Dalli ]----------------------------------<

@current_recipe = "dalli"
@before_configs["dalli"].call if @before_configs["dalli"]
say_recipe 'Dalli'

gemfile_comment "Memcached client"

gem 'dalli'

inject_into_file "config/environments/production.rb", after: "config.action_controller.perform_caching = true\n" do
  " config.cache_store = :dalli_store\n"
end

# >---------------------------------[ RailsAdmin ]----------------------------------<

@current_recipe = "rails_admin"
@before_configs["rails_admin"].call if @before_configs["rails_admin"]
say_recipe 'RailsAdmin'

gemfile_comment "Admin GUI"

gem 'rails_admin'

after_bundler do
  generate 'rails_admin:install'

  inject_into_file "config/initializers/rails_admin.rb", after: "# config.current_user_method(&:current_user)\n" do
<<-RUBY
  config.authenticate_with do
    warden.authenticate! scope: :admin_user
  end
  config.current_user_method(&:current_admin_user)

RUBY
  end

  create_file "config/initializers/rails_admin_types.rb" do
<<-RUBY
class RailsAdmin::Config::Fields::Types::Uuid < RailsAdmin::Config::Fields::Base
  RailsAdmin::Config::Fields::Types::register(self)
end

RUBY
  end
end

# >---------------------------------[ NewRelic ]----------------------------------<

say_recipe 'NewRelic'

gemfile_comment "Performance monitor"

gem 'newrelic_rpm'

# >---------------------------------[ Rspec ]----------------------------------<

say_recipe 'Rspec'

gem_group :test do
  gem 'rspec-rails', '>= 3.0'
  gem 'rspec-collection_matchers'
  gem 'factory_girl_rails'
  gem 'shoulda-matchers'
  gem 'simplecov'
  gem 'spring-commands-rspec'
end

create_file ".simplecov" do
%q{
SimpleCov.start 'rails' do
  add_filter '/spec/'
  add_filter '/db/'
  add_filter '/vendor'

  add_group 'API Controllers', 'app/controllers/api/'
  add_group 'Web Controllers' do |src_file|
    src_file.filename =~ /app\/controllers/ && not(src_file.filename =~ /app\/controllers\/api/)
  end
  add_group 'Decorators', 'app/decorators'
  add_group 'Helpers', 'app/helpers'
  add_group 'Mailers', 'app/mailers'
  add_group 'Models', 'app/models'
  add_group 'Services', 'app/services'
  add_group 'Lib', 'lib'
end

coverage_dir = "coverage"
# You can customize the folder to store the coverage report here.
SimpleCov.coverage_dir coverage_dir

}
end

after_bundler do
  generate 'rspec:install'

  inject_into_file "spec/rails_helper.rb", after: "RSpec.configure do |config|\n" do
    " config.include FactoryGirl::Syntax::Methods"
  end
end

# >---------------------------------[ Test/Development tools ]----------------------------------<

say_recipe 'Test/Development tools'

gem_group :test, :development do
  gem 'annotate', '>= 2.6.2'
  gem 'pry-rails'
  gem 'byebug'
  gem 'better_errors'
  gem 'quiet_assets'
  gem 'html2haml'
  gem 'faker'
  gemfile_comment "Web server"
  gem 'thin', require: false
end

after_bundler do
  run "bundle exec spring binstub --all"
end

# >---------------------------------[ Unicorn ]----------------------------------<

say_recipe 'Unicorn'

gem_group :staging, :production do
  gem 'unicorn', '>= 4.8.3'
end

create_file "config/unicorn.rb" do
%q{
worker_processes Integer(ENV["WEB_CONCURRENCY"] || 3)
timeout 30
preload_app true

before_fork do |server, worker|
  Signal.trap 'TERM' do
    puts 'Unicorn master intercepting TERM and sending myself QUIT instead'
    Process.kill 'QUIT', Process.pid
  end

  defined?(ActiveRecord::Base) and
    ActiveRecord::Base.connection.disconnect!
end

after_fork do |server, worker|
  Signal.trap 'TERM' do
    puts 'Unicorn worker intercepting TERM and doing nothing. Wait for master to send QUIT'
  end

  defined?(ActiveRecord::Base) and
    ActiveRecord::Base.establish_connection
end

}
end

# >----------------------------------[ Git ]----------------------------------<

say_recipe 'Git'

after_everything do
  run "cp config/database.yml config/database.yml.example"

  append_to_file '.gitignore' do
<<-GIT
/public/system/*
/public/assets
/public/photos

/coverage
/config/database.yml

# Mac
.DS_Store

GIT
  end

  git :add => '.'
  git :commit => '-m "Initialize project."'
end

# >-----------------------------[ config.ru ]-------------------------------<

say_recipe 'config.ru'

after_bundler do
  inject_into_file "config.ru", before: "run Rails.application\n" do
    "use Rack::Deflater\n"
  end
end

# >-----------------------------[ Run Bundler ]-------------------------------<

@current_recipe = nil

say_wizard "Running Bundler install. This will take a while."
run 'bundle install'
say_wizard "Running after Bundler callbacks."
@after_blocks.each{|b| config = @configs[b[0]] || {}; @current_recipe = b[0]; b[1].call}

@current_recipe = nil
say_wizard "Running after everything callbacks."
@after_everything_blocks.each{|b| config = @configs[b[0]] || {}; @current_recipe = b[0]; b[1].call}
