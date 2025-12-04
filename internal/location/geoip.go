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
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resultCh := make(chan ipapiResponse, 1)
	errCh := make(chan error, 3)
	
	// Use a clean, standard client to avoid interference from the app's complex networking logic
	cleanClient := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			Proxy:             http.ProxyFromEnvironment,
		},
	}

	url := "https://api.ipapi.is/"
	attempts := 3
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
		// Collect errors for debugging
		close(errCh)
		var errs []string
		for e := range errCh {
			errs = append(errs, e.Error())
		}
		if len(errs) > 0 {
			return 0, 0, fmt.Errorf("geoip failed: %s", fmt.Sprint(errs))
		}
		return 0, 0, fmt.Errorf("geoip timed out")
	}
}
