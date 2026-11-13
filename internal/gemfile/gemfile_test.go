package gemfile

import "testing"

func TestGroups(t *testing.T) {
	src := `source "https://rubygems.org"
gem "rails", "~> 7.1", ">= 7.1.2"
gem "pg" # database
gem "debug", platforms: %i[mri windows], group: :development
gem "rubocop", require: false, groups: [:development, :lint]
gem "bootsnap", group: [:default, :development]

group :development, :test do
  gem "rspec-rails"
  platforms :mri do
    gem "byebug"
  end
end

group :production do
  gem "lograge"
end
`
	want := map[string]struct {
		req string
		dev bool
	}{
		"rails": {"~> 7.1, >= 7.1.2", false}, "pg": {"", false}, "debug": {"", true}, "rubocop": {"", true},
		"bootsnap": {"", false}, "rspec-rails": {"", true}, "byebug": {"", true}, "lograge": {"", false},
	}
	got := Parse(src)
	if len(got) != len(want) {
		t.Fatalf("%d gems: %+v", len(got), got)
	}
	for _, g := range got {
		w := want[g.Name]
		if g.Requirement != w.req || g.DevOnly != w.dev {
			t.Errorf("%s: %+v, want %+v", g.Name, g, w)
		}
	}
}
