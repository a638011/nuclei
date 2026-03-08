package component

import (
	"net/http"
	"testing"

	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

func TestURLComponent(t *testing.T) {
	req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com/testpath", nil)
	if err != nil {
		t.Fatal(err)
	}

	urlComponent := NewPath()
	_, err = urlComponent.Parse(req)
	if err != nil {
		t.Fatal(err)
	}

	var keys []string
	var values []string
	_ = urlComponent.Iterate(func(key string, value interface{}) error {
		keys = append(keys, key)
		values = append(values, value.(string))
		return nil
	})

	require.Equal(t, []string{"1"}, keys, "unexpected keys")
	require.Equal(t, []string{"testpath"}, values, "unexpected values")

	err = urlComponent.SetValue("1", "newpath")
	if err != nil {
		t.Fatal(err)
	}

	rebuilt, err := urlComponent.Rebuild()
	if err != nil {
		t.Fatal(err)
	}
	require.Equal(t, "/newpath", rebuilt.Path, "unexpected URL path")
	require.Equal(t, "https://example.com/newpath", rebuilt.String(), "unexpected full URL")
}

func TestURLComponent_NestedPaths(t *testing.T) {
	path := NewPath()
	req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com/user/753/profile", nil)
	if err != nil {
		t.Fatal(err)
	}
	found, err := path.Parse(req)
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("expected path to be found")
	}

	isSet := false

	_ = path.Iterate(func(key string, value interface{}) error {
		t.Logf("Key: %s, Value: %s", key, value.(string))
		if !isSet && value.(string) == "753" {
			isSet = true
			if setErr := path.SetValue(key, "753'"); setErr != nil {
				t.Fatal(setErr)
			}
		}
		return nil
	})

	newReq, err := path.Rebuild()
	if err != nil {
		t.Fatal(err)
	}
	if newReq.Path != "/user/753'/profile" {
		t.Fatalf("expected path to be '/user/753'/profile', got '%s'", newReq.Path)
	}
}

func TestPathComponent_SQLInjection(t *testing.T) {
	path := NewPath()
	req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com/user/55/profile", nil)
	if err != nil {
		t.Fatal(err)
	}
	found, err := path.Parse(req)
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("expected path to be found")
	}

	t.Logf("Original path: %s", req.Path)

	// Let's see what path segments are available for fuzzing
	err = path.Iterate(func(key string, value interface{}) error {
		t.Logf("Key: %s, Value: %s", key, value.(string))

		// Try fuzzing the "55" segment specifically (which should be key "2")
		if value.(string) == "55" {
			if setErr := path.SetValue(key, "55 OR True"); setErr != nil {
				t.Fatal(setErr)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	newReq, err := path.Rebuild()
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Modified path: %s", newReq.Path)

	// Now with PathEncode, spaces are preserved correctly for SQL injection
	if newReq.Path != "/user/55 OR True/profile" {
		t.Fatalf("expected path to be '/user/55 OR True/profile', got '%s'", newReq.Path)
	}

	// Let's also test what the actual URL looks like
	t.Logf("Full URL: %s", newReq.String())
}

func TestPathComponent_DeterministicOrder(t *testing.T) {
	// Regression test for #6398: path segments must iterate in insertion order
	// to ensure all segments (including numeric ones) are fuzzed deterministically.
	for run := 0; run < 50; run++ {
		path := NewPath()
		req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com/user/55/profile", nil)
		if err != nil {
			t.Fatal(err)
		}
		found, err := path.Parse(req)
		if err != nil {
			t.Fatal(err)
		}
		if !found {
			t.Fatal("expected path to be found")
		}

		var keys []string
		var values []string
		_ = path.Iterate(func(key string, value interface{}) error {
			keys = append(keys, key)
			values = append(values, value.(string))
			return nil
		})

		require.Equal(t, []string{"1", "2", "3"}, keys, "run %d: keys must be in insertion order", run)
		require.Equal(t, []string{"user", "55", "profile"}, values, "run %d: values must be in insertion order", run)
	}
}

func TestPathComponent_EmptySegmentsPreserved(t *testing.T) {
	// Test that empty path segments (e.g., from "/a//b/" or trailing slash) are preserved
	testCases := []struct {
		name         string
		inputPath    string
		expectedPath string
	}{
		{
			name:         "double slash in middle",
			inputPath:    "https://example.com/a//b",
			expectedPath: "/a//b",
		},
		{
			name:         "trailing slash",
			inputPath:    "https://example.com/a/b/",
			expectedPath: "/a/b/",
		},
		{
			name:         "multiple empty segments",
			inputPath:    "https://example.com/a///b/",
			expectedPath: "/a///b/",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			path := NewPath()
			req, err := retryablehttp.NewRequest(http.MethodGet, tc.inputPath, nil)
			require.NoError(t, err)

			found, err := path.Parse(req)
			require.NoError(t, err)
			require.True(t, found)

			rebuilt, err := path.Rebuild()
			require.NoError(t, err)
			require.Equal(t, tc.expectedPath, rebuilt.Path, "empty segments should be preserved")
		})
	}
}

func TestPathComponent_RebuildUsesOriginalPathSnapshot(t *testing.T) {
	// Test that Rebuild() doesn't mutate the original request
	path := NewPath()
	req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com/user/123/profile", nil)
	require.NoError(t, err)

	originalPath := req.Path
	originalURL := req.URL.String()

	found, err := path.Parse(req)
	require.NoError(t, err)
	require.True(t, found)

	// Modify a segment
	err = path.SetValue("2", "456")
	require.NoError(t, err)

	// Rebuild should not mutate the original request
	rebuilt, err := path.Rebuild()
	require.NoError(t, err)

	// Verify the original request is unchanged
	require.Equal(t, originalPath, req.Path, "original request path should not be mutated")
	require.Equal(t, originalURL, req.URL.String(), "original request URL should not be mutated")

	// Verify the rebuilt request has the new value
	require.Equal(t, "/user/456/profile", rebuilt.Path, "rebuilt path should have the new value")
}

func TestPathComponent_ExplicitEmptyReplacement(t *testing.T) {
	// Test that explicit empty replacement values are respected (not treated as "missing")
	path := NewPath()
	req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com/user/123/profile", nil)
	require.NoError(t, err)

	found, err := path.Parse(req)
	require.NoError(t, err)
	require.True(t, found)

	// Explicitly set a segment to an empty string
	err = path.SetValue("2", "")
	require.NoError(t, err)

	rebuilt, err := path.Rebuild()
	require.NoError(t, err)

	// The empty replacement should be used, resulting in "/user//profile"
	require.Equal(t, "/user//profile", rebuilt.Path, "explicit empty replacement should be respected")
}
