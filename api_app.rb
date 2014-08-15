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

# We have some problem with Spring, have to stop it before setting up anything.
after_bundler do
  run "spring stop"
end

# >-----------------------------[ ActiveRecord ]------------------------------<

@current_recipe = "activerecord"
@before_configs["activerecord"].call if @before_configs["activerecord"]
say_recipe 'ActiveRecord'

config = {}
config['database'] = 'postgresql'
@configs[@current_recipe] = config

old_gem = gem_for_database
old_options = @options.dup
@options = @options.dup.merge(database: config['database'])
inject_into_file "Gemfile", after: "gem '#{old_gem}'\n" do
  "gem '#{gem_for_database}'\n"
end

# Revert back to the original gem, we will change it later.
@options = old_options

after_everything do
  say_wizard "Configuring '#{config['database']}' database settings..."
  @options = @options.dup.merge(database: config['database'])
  gsub_file 'Gemfile', "gem '#{old_gem}'", ""
  template "config/databases/#{@options[:database]}.yml", "config/database.yml.new"
  run 'mv config/database.yml.new config/database.yml'
end

# >---------------------------------[ Rspec ]----------------------------------<

say_recipe 'Rspec'

gem_group :test, :development do
  gem 'rspec-rails', '>= 3.0'
  gem 'factory_girl_rails'
  gem 'faker'
end

gem_group :test do
  gem 'rspec-collection_matchers'
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
    "  config.include FactoryGirl::Syntax::Methods\n"
  end
end

after_everything do
  run "rm -rf test/"
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
  gemfile_comment "Web server"
  gem 'thin', require: false
end

after_bundler do
  run "bundle exec spring binstub --all"
end

# >---------------------------------[ DB rake tasks ]----------------------------------<

say_recipe 'DB rake tasks'

create_file "lib/tasks/db_util.rake" do
%q{namespace :db do
  desc "Drop, re-create and re-seed database"
  task :reinit => [:drop, :create, :migrate, :seed]

  desc "Drop, re-create and populate sample data"
  task :bootstrap => [:reinit, :sample_data]

  desc "Load the sample data from db/sample_data.rb"
  task :sample_data => :environment do
    sample_file = File.join(Rails.root, 'db', 'sample_data.rb')
    load(sample_file) if File.exist?(sample_file)
  end
end
}
end

create_file "db/sample_data.rb" do
%q{
# This file is to generate a large number of dummy data to save time in development.
# This file is loaded by rake db:sample_data or rake db:bootstrap
# DB should be cleand up before calling this file.
# DO NOT run this file in production!

# Handle number of sample records for each type, and calculate batch import size
# You can run: rake db:bootstrap n=20000 p=500
num = ENV['n'].to_i
num = 10000 if num <= 0
page_size = ENV['p'].to_i
page_size = 200 if page_size <= 0
pages = (num.to_f/page_size).ceil

# Default password for all users.
PASSWORD = "123456"
}
end

TIME_FORMAT = "%Y%m%d%H%M%S"
fingersprint = "#{Time.now.strftime(TIME_FORMAT)}"

create_file "db/migrate/#{fingersprint}_enable_uuid_ossp_extension.rb" do
%q{class EnableUuidOsspExtension < ActiveRecord::Migration
  def change
    enable_extension 'uuid-ossp'
  end
end
}
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
  create_file 'config/api-keys.yml.erb' do
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

    config.exceptions_app = self.routes
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
  "  config.cache_store = :dalli_store\n"
end

gsub_file "config/environments/test.rb", "config.action_controller.perform_caching = false", "config.action_controller.perform_caching = true"

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
  run "mv README.rdoc README.md"

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

# >-----------------------------[ Template files ]-------------------------------<

say_recipe 'Generate some place holder files'

after_bundler do
  create_file "app/controllers/home_controller.rb" do
%q{class HomeController < ApplicationController
  def index
    render nothing: true
  end
end
}
  end

  inject_into_file "config/routes.rb", after: "Rails.application.routes.draw do\n" do
    %q{  root to: "home#index"
}
  end

  run "mkdir -p app/controllers/api/v1"
  run "rm app/controllers/application_controller.rb"

  create_file "app/controllers/application_controller.rb" do
%q{class ApplicationController < ActionController::Base
  PAGE_SIZE = 20
  MAX_PAGE_SIZE = 100

  include ApplicationHelper
  protect_from_forgery

  before_filter :filter_params

  before_filter :configure_permitted_parameters, if: :devise_controller?

  # Register error handling.
  # We encapsulate `rescue_from` code in this method so that it's easier for testing.
  def self.rescue_from_errors
    rescue_from Exception, :with => :render_unknown_error
    # Handle strong_parameters exception
    rescue_from ActionController::ParameterMissing, with: :render_invalid_params
    rescue_from ActionController::UnpermittedParameters, with: :render_invalid_params
    rescue_from ActiveRecord::RecordNotFound, :with => :render_not_found
    rescue_from ActionController::RoutingError, :with => :render_not_found
    rescue_from CanCan::AccessDenied, :with => :render_unauthorized
  end

  def raise_not_found!
    raise ActionController::RoutingError.new(
      "No route matches #{params[:unmatched_route]}"
    )
  end

  unless Rails.application.config.consider_all_requests_local
    rescue_from_errors
  end

  def render_invalid_params(exception)
    render_error(
      message: exception.message,
      status: 400,
      redirect_to: root_path
    )
  end

  def render_not_found(exception = nil)
    render_error(
      status: 404,
      template: 'errors/404'
    )
  end

  def render_unauthorized(exception = nil)
    render_error(
      message: "You are not authorized to access the page!",
      status: 403,
      redirect_to: root_path
    )
  end

  def render_unknown_error(exception)
    Util.log_error(exception)
    render_error
  end

  # Template method to render error.
  #
  # == Parameters
  #
  #   * options[:status]: status code.
  #   * options[:template]: template.
  #   * options[:layout]: layout.
  #   * options[:redirect_to]: redirect URL.
  #     If this value is set, the method 'redirect_to' will be used instead of 'render'.
  #
  def render_error(options = {})
    # Set default options
    options = {
      status: 500,
      template: 'errors/500',
      layout: 'layouts/application'
    }.merge!(options)

    message = options[:message]

    respond_to do |format|
      format.html {
        flash[:error] = message
        redirect_url = options[:redirect_to]
        if redirect_url
          redirect_to redirect_url
        else
          render options
        end
      }

      format.any do
        render json: {error: message}, status: options[:status]
      end
    end
  end

  protected

  def configure_permitted_parameters
    devise_parameter_sanitizer.for(:sign_up) do |u|
      u.permit(
        :username,
        :email,
        :name,
        :password,
        :password_confirmation,
        :social_provider,
        :social_uid
      )
    end
  end

  # You can override this method in the sub class.
  # Or define action-based page size method like this:
  #
  # def replies
  #
  # end
  #
  # protected
  # def page_size_for_replies
  #   10
  # end
  #
  # The method :page_size_for_replies will be auto called
  # when the action :replies is hit.
  #
  def default_page_size
    PAGE_SIZE
  end

  def filter_params
    # Check the per_page params.
    unless params[:per_page]
      # To support action-based page size.
      # Try to call :page_size_for_<action_name> firstly.
      # then use :default_page_size if the method isn't defined.
      params[:per_page] = self.try("page_size_for_#{action_name}") || default_page_size
    else
      limit_page_size
    end
    params
  end

  def limit_page_size
    if params[:per_page].to_i > MAX_PAGE_SIZE
      # To avoid returning too much data for the kids ;)
      params[:per_page] = MAX_PAGE_SIZE
    end
    params
  end
end
}
  end

  create_file "app/controllers/api/v1/api_base_controller.rb" do
%q{module Api::V1
  class ApiBaseController < ApplicationController
    include ActionController::HttpAuthentication::Token

    REQUEST_SUCCEEDED = 200
    BAD_REQUEST_ERROR = 400
    UNPROCESSABLE_ENTITY = 422
    UNAUTHORIZED_ERROR = 401
    UNKNOWN_ERROR = 402
    INTERNAL_ERROR = 500
    NOT_FOUND_ERROR = 404

    skip_before_filter :verify_authenticity_token, :if => Proc.new { |c| c.request.format == 'application/json' }
    before_filter :restrict_access

    protected

    def restrict_access
      authenticate_or_request_with_http_token do |token, options|
        if current_user
          # Do something here...
        end
        current_user
      end
    end

    def current_user
      return @current_user if @current_user

      token, _ = token_and_options(request)
      @current_user = user_by_token(token)
    end

    def user_by_token(token)
      # TODO: implement this method.
      # Authentication.where(token: token).first.try(:user)
    end

    def render_objects(objects, &block)
      pagination = ApiPayloadHelper.pagination_info(objects, params[:per_page])

      render json: ApiPayloadHelper.success_payload(objects, pagination, &block),
             status: REQUEST_SUCCEEDED
    end

    def render_objects_with_paging(objects, &block)
      _objects = objects.page(params[:page]).per(params[:per_page])
      render_objects(_objects, &block)
    end

    def log_api_error(msg)
      if current_user
        Rails.logger.error "APIV1 ERROR [#{current_user.username}]:: #{msg}"
      else
        Rails.logger.error "APIV1 ERROR [Anonymous]:: #{msg}"
      end
    end
  end
end
}
  end

  run "mkdir spec/support"
  create_file "spec/support/devise.rb" do
%q{module UserSessionRequestHelper
  def sign_in(user)
    post_via_redirect user_session_path, user: {username: user.username, password: user.password}
  end
end

RSpec.configure do |config|
  config.include Devise::TestHelpers, :type => :controller
  config.include UserSessionRequestHelper, :type => :request
end
}
  end

  create_file "spec/support/paperclip.rb" do
%q{require "paperclip/matchers"

RSpec.configure do |config|
  config.include Paperclip::Shoulda::Matchers
end
}
  end

  create_file "spec/support/shared_examples.rb" do
%q{shared_examples_for "api_unauthorized" do |actions, extra_params = {}|
  context "without token" do
    before { clear_api_auth }

    actions.each do |action, method|
      it "returns #{Api::V1::ApiBaseController::UNAUTHORIZED_ERROR} for action #{action}" do
        send(method, action, {id: 'some_id', format: :json}.merge(extra_params))
        assert_response Api::V1::ApiBaseController::UNAUTHORIZED_ERROR
      end
    end
  end
end

# Require let(:controller) {}
shared_examples_for "api_routing" do |params|
  it "routes #{params[:method].to_s.upcase} '#{params[:url]}' to '#{params[:action]}'" do

    expectation = {
      controller: controller,
      action: params[:action],
      format: 'json'
    }

    unless params[:params].blank?
      expectation.merge!(params[:params])
    end

    expect(params[:method] => params[:url]).to route_to(expectation)
  end
end

# Require let(:controller) {}
shared_examples_for "web_routing" do |params|
  it "routes #{params[:method].to_s.upcase} '#{params[:url]}' to '#{params[:action]}'" do

    expectation = {
      controller: controller,
      action: params[:action]
    }

    unless params[:params].blank?
      expectation.merge!(params[:params])
    end

    expect(params[:method] => params[:url]).to route_to(expectation)
  end
end

shared_examples_for "web_not_found" do
  it "returns 404 Not found" do
    expect { subject }.to raise_error(ActiveRecord::RecordNotFound)
  end
end

shared_examples_for "api_not_found" do
  it_behaves_like "web_not_found"
end

shared_examples_for "api_missing_params" do
  it "returns 400 Bad Request" do
    expect { subject }.to raise_error(ActionController::ParameterMissing)
  end
end

shared_examples_for "unauthorized_error" do
  it "raises CanCan::AccessDenied error" do
    expect { subject }.to raise_error(CanCan::AccessDenied)
  end
end
}
  end

  create_file "spec/support/utils.rb" do
    ""
  end

  run "mkdir app/services"

  create_file "app/services/api_payload_helper.rb" do
%q{class ApiPayloadHelper
  class << self
    def pagination_info(arr, per_page)
      {
        per_page: per_page.to_i,
        page: arr.current_page,
        total_pages: arr.total_pages
      }
    end

    def success_payload(object, pagination = {}, &block)
      if object.is_a?(Array) || object.is_a?(ActiveRecord::Relation)
        _object = object
        if block
          _object = objects_payload(_object, &block)
        end

        json = {
          objects: _object,
          pagination: pagination
        }
      else
        json = object
      end
      json
    end

    def objects_payload(objects, &block)
      objects.map { |obj| yield(obj) }
    end
  end
end
}
  end

  # Fixture
  run "mkdir -p spec/fixtures/files"
  run "touch spec/fixtures/files/.keep"

  # Request specs.
  run "mkdir -p spec/requests"
  run "touch spec/requests/.keep"

  # Service specs.
  run "mkdir -p spec/services"
  run "touch spec/services/.keep"

  # Library specs.
  run "mkdir -p spec/lib"
  run "touch spec/lib/.keep"

  # Routing specs.
  run "mkdir -p spec/routing/api/v1"
  run "touch spec/routing/api/v1/.keep"
end

after_everything do
  inject_into_file "config/routes.rb", before: "\nend" do
%q{
  match "404", to: "application#render_not_found", via: :all
  match "*unmatched_route", to: "application#raise_not_found!", via: :all
}
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
