// Copyright 2014 Canonical Ltd.
// Licensed under the LGPLv3, see LICENCE file for details.

package elasticsearch

import (
	"testing"

	jujutesting "github.com/juju/testing"
	gc "launchpad.net/gocheck"
)

func TestPackage(t *testing.T) {
	ElasticSearchTestPackage(t)
}

type IsolatedElasticSearchSuite struct {
	jujutesting.IsolationSuite
	ElasticSearchSuite
}

func (s *IsolatedElasticSearchSuite) SetUpSuite(c *gc.C) {
	s.IsolationSuite.SetUpSuite(c)
	s.ElasticSearchSuite.SetUpSuite(c)
}
func (s *IsolatedElasticSearchSuite) TearDownSuite(c *gc.C) {
	s.IsolationSuite.TearDownSuite(c)
	s.ElasticSearchSuite.TearDownSuite(c)
}
func (s *IsolatedElasticSearchSuite) SetUpTest(c *gc.C) {
	s.IsolationSuite.SetUpTest(c)
	s.ElasticSearchSuite.SetUpTest(c)
}
func (s *IsolatedElasticSearchSuite) TearDownTest(c *gc.C) {
	s.IsolationSuite.TearDownTest(c)
	s.ElasticSearchSuite.TearDownTest(c)
}

var _ = gc.Suite(&IsolatedElasticSearchSuite{})

func (s *ElasticSearchSuite) TestSuccessfulAdd(c *gc.C) {
	doc := map[string]string{
		"a": "b",
	}
	err := s.db.AddNewEntity(doc)
	c.Assert(err, gc.IsNil)
}
