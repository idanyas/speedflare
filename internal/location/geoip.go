package location

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

type ipapiResponse struct {
	Location struct {
		Latitude  float64 `json:"latitude"`
		Longitude float64 `json:"longitude"`
	} `json:"location"`
}

// GetUserCoordinates performs 3 parallel requests to api.ipapi.is using a clean HTTP client.
// It returns the fastest result.
func GetUserCoordinates() (float64, float64, error) {
	// Increased timeout to handle slower connections
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	attempts := 3
	resultCh := make(chan ipapiResponse, 1)
	// Buffer equals attempts to ensure goroutines never block on send,
	// allowing us to avoid closing the channel (preventing panics on race conditions).
	errCh := make(chan error, attempts)

	// Use a clean, standard client to avoid interference from the app's complex networking logic
	cleanClient := &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			Proxy:             http.ProxyFromEnvironment,
		},
	}

	url := "https://api.ipapi.is/"
	var wg sync.WaitGroup

	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
			if err != nil {
				errCh <- err
				return
			}
			// Mimic a browser to ensure we aren't blocked
			req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Speedflare/1.0)")

			resp, err := cleanClient.Do(req)
			if err != nil {
				errCh <- err
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				errCh <- fmt.Errorf("status %d", resp.StatusCode)
				return
			}

			var data ipapiResponse
			if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
				errCh <- err
				return
			}

			// Validate result isn't empty (0,0 is possible but rare, usually implies failure in some APIs)
			if data.Location.Latitude == 0 && data.Location.Longitude == 0 {
				errCh <- fmt.Errorf("zero coordinates received")
				return
			}

			select {
			case resultCh <- data:
			case <-ctx.Done():
			}
		}(i)
	}

	// wait for results
	select {
	case res := <-resultCh:
		return res.Location.Latitude, res.Location.Longitude, nil
	case <-ctx.Done():
		// Collect errors that have arrived so far
		var errs []string
		count := len(errCh)
		for i := 0; i < count; i++ {
			select {
			case e := <-errCh:
				errs = append(errs, e.Error())
			default:
			}
		}
		if len(errs) > 0 {
			return 0, 0, fmt.Errorf("geoip failed: %s", fmt.Sprint(errs))
		}
		return 0, 0, fmt.Errorf("geoip timed out")
	}
}
