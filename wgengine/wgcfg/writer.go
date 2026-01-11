// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package wgcfg

import (
	"fmt"
	"io"
	"net/netip"
	"strconv"

	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

// ToUAPI writes cfg in UAPI format to w.
// Prev is the previous device Config.
//
// Prev is required so that we can remove now-defunct peers without having to
// remove and re-add all peers, and so that we can avoid writing information
// about peers that have not changed since the previous time we wrote our
// Config.
func (cfg *Config) ToUAPI(logf logger.Logf, w io.Writer, prev *Config) error {
	logf("wgcfg: ToUAPI called with %d peers", len(cfg.Peers))
	var stickyErr error
	set := func(key, value string) {
		if stickyErr != nil {
			return
		}
		_, err := fmt.Fprintf(w, "%s=%s\n", key, value)
		if err != nil {
			stickyErr = err
		}
	}
	setUint16 := func(key string, value uint16) {
		set(key, strconv.FormatUint(uint64(value), 10))
	}
	setPeer := func(peer Peer) {
		set("public_key", peer.PublicKey.UntypedHexString())
	}

	// Device config.
	if !prev.PrivateKey.Equal(cfg.PrivateKey) {
		set("private_key", cfg.PrivateKey.UntypedHexString())
	}

	// Set PQC seed if it has changed
	if len(cfg.PQCSeed) > 0 {
		if !bytesEqual(prev.PQCSeed, cfg.PQCSeed) {
			logf("wgcfg: setting device PQC private key (seed len=%d, changed from prev)", len(cfg.PQCSeed))
			set("pqc_private_key", fmt.Sprintf("%x", cfg.PQCSeed))
		} else {
			logf("wgcfg: device PQC seed unchanged (len=%d), not rewriting", len(cfg.PQCSeed))
		}
	} else {
		logf("wgcfg: device has no PQC seed to set")
	}

	old := make(map[key.NodePublic]Peer)
	for _, p := range prev.Peers {
		old[p.PublicKey] = p
	}

	// Add/configure all new peers.
	for _, p := range cfg.Peers {
		logf("wgcfg: WRITER processing peer %s (has %d bytes PQC key)", p.PublicKey.ShortString(), len(p.PQCPublicKey))
		oldPeer, wasPresent := old[p.PublicKey]

		// We only want to write the peer header/version if we're about
		// to change something about that peer, or if it's a new peer.
		// Figure out up-front whether we'll need to do anything for
		// this peer, and skip doing anything if not.
		//
		// If the peer was not present in the previous config, this
		// implies that this is a new peer; set all of these to 'true'
		// to ensure that we're writing the full peer configuration.
		willSetEndpoint := oldPeer.WGEndpoint != p.PublicKey || !wasPresent
		willChangeIPs := !cidrsEqual(oldPeer.AllowedIPs, p.AllowedIPs) || !wasPresent
		willChangeKeepalive := oldPeer.PersistentKeepalive != p.PersistentKeepalive // if not wasPresent, no need to redundantly set zero (default)
		willChangePQC := !bytesEqual(oldPeer.PQCPublicKey, p.PQCPublicKey) || !wasPresent

		if !willSetEndpoint && !willChangeIPs && !willChangeKeepalive && !willChangePQC {
			// It's safe to skip doing anything here; wireguard-go
			// will not remove a peer if it's unspecified unless we
			// tell it to (which we do below if necessary).
			if len(p.PQCPublicKey) > 0 {
				logf("wgcfg: peer %s: skipping (no changes), has PQC key (len=%d)", p.PublicKey.ShortString(), len(p.PQCPublicKey))
			}
			continue
		}

		setPeer(p)
		set("protocol_version", "1")

		// Avoid setting endpoints if the correct one is already known
		// to WireGuard, because doing so generates a bit more work in
		// calling magicsock's ParseEndpoint for effectively a no-op.
		if willSetEndpoint {
			if wasPresent {
				// We had an endpoint, and it was wrong.
				// By construction, this should not happen.
				// If it does, keep going so that we can recover from it,
				// but log so that we know about it,
				// because it is an indicator of other failed invariants.
				// See corp issue 3016.
				logf("[unexpected] endpoint changed from %s to %s", oldPeer.WGEndpoint, p.PublicKey)
			}
			set("endpoint", p.PublicKey.UntypedHexString())
		}

		// TODO: replace_allowed_ips is expensive.
		// If p.AllowedIPs is a strict superset of oldPeer.AllowedIPs,
		// then skip replace_allowed_ips and instead add only
		// the new ipps with allowed_ip.
		if willChangeIPs {
			set("replace_allowed_ips", "true")
			for _, ipp := range p.AllowedIPs {
				set("allowed_ip", ipp.String())
			}
		}

		// Set PQC public key if changed
		logf("wgcfg: WRITER peer %s: willChangePQC=%v, hasPQC=%v, len=%d, wasPresent=%v", p.PublicKey.ShortString(), willChangePQC, len(p.PQCPublicKey) > 0, len(p.PQCPublicKey), wasPresent)
		if len(p.PQCPublicKey) > 0 {
			if willChangePQC {
				logf("wgcfg: setting peer %s PQC public key (len=%d, wasPresent=%v)", p.PublicKey.ShortString(), len(p.PQCPublicKey), wasPresent)
				set("pqc_public_key", fmt.Sprintf("%x", p.PQCPublicKey))
			} else {
				logf("wgcfg: peer %s PQC public key unchanged (len=%d), not rewriting", p.PublicKey.ShortString(), len(p.PQCPublicKey))
			}
		} else {
			logf("wgcfg: peer %s has NO PQC public key", p.PublicKey.ShortString())
		}

		// Set PersistentKeepalive after the peer is otherwise configured,
		// because it can trigger handshake packets.
		if willChangeKeepalive {
			setUint16("persistent_keepalive_interval", p.PersistentKeepalive)
		}
	}

	// Remove peers that were present but should no longer be.
	for _, p := range cfg.Peers {
		delete(old, p.PublicKey)
	}
	for _, p := range old {
		setPeer(p)
		set("remove", "true")
	}

	if stickyErr != nil {
		stickyErr = fmt.Errorf("ToUAPI: %w", stickyErr)
	}
	return stickyErr
}

func cidrsEqual(x, y []netip.Prefix) bool {
	// TODO: re-implement using netaddr.IPSet.Equal.
	if len(x) != len(y) {
		return false
	}
	// First see if they're equal in order, without allocating.
	exact := true
	for i := range x {
		if x[i] != y[i] {
			exact = false
			break
		}
	}
	if exact {
		return true
	}

	// Otherwise, see if they're the same, but out of order.
	m := make(map[netip.Prefix]bool)
	for _, v := range x {
		m[v] = true
	}
	for _, v := range y {
		if !m[v] {
			return false
		}
	}
	return true
}

func bytesEqual(x, y []byte) bool {
	if len(x) != len(y) {
		return false
	}
	if len(x) == 0 {
		return true
	}
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}
