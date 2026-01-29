package location

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/idanyas/speedflare/internal/data"
)

var probeRanges = []string{
	"162.159.128.0/19",
	"104.16.176.0/20",
	"172.66.40.0/21",
	"172.67.176.0/20",
	"188.114.97.0/24",
}

const (
	probeCountPerRange = 255
	earthRadiusKm      = 6371.0
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

// ProbeColos determines the closest servers.
// userLat/userLon: Explicit coordinates from GeoIP (Approach 1).
// userColo: The 'colo' code from trace (Approach 2/Fallback: use this colo's loc as reference).
// userCountryCode: The country code (Legacy fallback).
func ProbeColos(userLat, userLon float64, userColo string, userCountryCode string, allLocs []data.Location) ([]data.Server, error) {
	var ips []string
	for _, cidr := range probeRanges {
		generated, err := generateRandomIPs(cidr, probeCountPerRange)
		if err == nil {
			ips = append(ips, generated...)
		}
	}

	type probeResult struct {
		Colo string
		IP   string
	}
	results := make(chan probeResult, len(ips))
	var wg sync.WaitGroup

	// Use high concurrency for speed
	workerLimit := make(chan struct{}, 256)

	for _, ip := range ips {
		wg.Add(1)
		go func(targetIP string) {
			defer wg.Done()
			workerLimit <- struct{}{}
			defer func() { <-workerLimit }()

			colo, err := probeSingleIP(targetIP)
			if err == nil && colo != "" {
				results <- probeResult{Colo: colo, IP: targetIP}
			}
		}(ip)
	}

	wg.Wait()
	close(results)

	uniqueColos := make(map[string]string)
	for res := range results {
		if _, exists := uniqueColos[res.Colo]; !exists {
			uniqueColos[res.Colo] = res.IP
		}
	}

	// Calculate reference coordinates
	var refLat, refLon float64
	var hasReference bool

	// Priority 1: Explicit Coordinates (from GeoIP API)
	if userLat != 0 || userLon != 0 {
		refLat = userLat
		refLon = userLon
		hasReference = true
	} else {
		// Priority 2: Fallback to the Primary Colo location (Using our "library" of locations)
		// This is much better than hardcoded capitals for large countries (e.g. Vladivostok vs Moscow).
		if primaryInfo, err := FindServerInfo(userColo, allLocs); err == nil {
			refLat = primaryInfo.Lat
			refLon = primaryInfo.Lon
			hasReference = true
		} else {
			// Priority 3: Centroid of all servers in country (Old logic - worst case fallback)
			var latSum, lonSum float64
			var count int
			for _, l := range allLocs {
				if l.CCA2 == userCountryCode {
					latSum += l.Lat
					lonSum += l.Lon
					count++
				}
			}
			if count > 0 {
				refLat = latSum / float64(count)
				refLon = lonSum / float64(count)
				hasReference = true
			}
		}
	}

	var servers []data.Server
	for colo, ip := range uniqueColos {
		info, err := FindServerInfo(colo, allLocs)
		if err != nil {
			continue
		}
		info.IP = ip
		if hasReference {
			info.Distance = haversine(refLat, refLon, info.Lat, info.Lon)
		}
		servers = append(servers, info)
	}

	sort.Slice(servers, func(i, j int) bool {
		// Priority 1: Same country as user
		s1InCountry := servers[i].Country == userCountryCode
		s2InCountry := servers[j].Country == userCountryCode

		if s1InCountry && !s2InCountry {
			return true
		}
		if !s1InCountry && s2InCountry {
			return false
		}

		// Priority 2: Distance (if available)
		if hasReference {
			if math.Abs(servers[i].Distance-servers[j].Distance) > 1.0 { // tolerance
				return servers[i].Distance < servers[j].Distance
			}
		}

		// Priority 3: Alphabetical IATA
		return servers[i].IATA < servers[j].IATA
	})

	return servers, nil
}

func probeSingleIP(ip string) (string, error) {
	// Increased timeouts slightly to avoid skipping good servers on jittery lines
	dialer := &net.Dialer{
		Timeout: 1500 * time.Millisecond,
	}

	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp4", net.JoinHostPort(ip, "443"))
		},
		TLSHandshakeTimeout: 1500 * time.Millisecond,
		DisableKeepAlives:   true,
		TLSClientConfig: &tls.Config{
			ServerName:         "speed.cloudflare.com",
			InsecureSkipVerify: true,
		},
		ForceAttemptHTTP2: true,
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   2500 * time.Millisecond,
	}

	resp, err := client.Get("https://speed.cloudflare.com/cdn-cgi/trace")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(line, "colo=") {
			parts := strings.Split(line, "=")
			if len(parts) == 2 {
				return parts[1], nil
			}
		}
	}
	return "", fmt.Errorf("no colo found")
}

func haversine(lat1, lon1, lat2, lon2 float64) float64 {
	dLat := (lat2 - lat1) * (math.Pi / 180.0)
	dLon := (lon2 - lon1) * (math.Pi / 180.0)

	lat1 = lat1 * (math.Pi / 180.0)
	lat2 = lat2 * (math.Pi / 180.0)

	a := math.Sin(dLat/2)*math.Sin(dLat/2) + math.Sin(dLon/2)*math.Sin(dLon/2)*math.Cos(lat1)*math.Cos(lat2)
	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))

	return earthRadiusKm * c
}

func generateRandomIPs(cidr string, count int) ([]string, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	mask, _ := ipnet.Mask.Size()
	size := 32 - mask
	totalHosts := 1 << size
	if totalHosts <= 0 {
		totalHosts = 1
	}

	var ips []string
	startIP := binary.BigEndian.Uint32(ipnet.IP)

	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	for i := 0; i < count; i++ {
		offset := r.Intn(totalHosts)
		ipInt := startIP + uint32(offset)

		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, ipInt)
		ips = append(ips, ip.String())
	}
	return ips, nil
}
