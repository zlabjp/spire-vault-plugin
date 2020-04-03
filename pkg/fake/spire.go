/**
 * Copyright 2020, Z Lab Corporation. All rights reserved.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

package fake

import (
	"github.com/spiffe/spire/proto/spire/server/upstreamauthority"
	"google.golang.org/grpc"
)

type UpstreamAuthorityMintX509CAServer struct {
	grpc.ServerStream

	WantError error
}

func (s *UpstreamAuthorityMintX509CAServer) Send(response *upstreamauthority.MintX509CAResponse) error {
	return s.WantError
}
