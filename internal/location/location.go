package location

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/idanyas/speedflare/internal/data"
)

func GetServerTrace(client *http.Client) (map[string]string, error) {
	resp, err := client.Get("https://speed.cloudflare.com/cdn-cgi/trace")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	info := make(map[string]string)
	for _, line := range strings.Split(string(body), "\n") {
		if parts := strings.SplitN(line, "=", 2); len(parts) == 2 {
			info[parts[0]] = parts[1]
		}
	}
	return info, nil
}

func FetchLocations(client *http.Client) ([]data.Location, error) {
	resp, err := client.Get("https://speed.cloudflare.com/locations")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var locations []data.Location
	if err := json.NewDecoder(resp.Body).Decode(&locations); err != nil {
		return nil, err
	}

	sort.Slice(locations, func(i, j int) bool {
		return locations[i].IATA < locations[j].IATA
	})

	return locations, nil
}

func FindServerInfo(iata string, locs []data.Location) (data.Server, error) {
	for _, loc := range locs {
		if loc.IATA == iata {
			return data.Server{
				IATA:    loc.IATA,
				City:    loc.City,
				Country: loc.CCA2,
				Lat:     loc.Lat,
				Lon:     loc.Lon,
			}, nil
		}
	}
	return data.Server{}, fmt.Errorf("server location not found")
}
