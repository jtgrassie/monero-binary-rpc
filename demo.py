#  Copyright (c) 2018-2019, Jethro Grassie
#  
#  All rights reserved.
#  
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are met:
#  
#  1. Redistributions of source code must retain the above copyright notice, this
#  list of conditions and the following disclaimer.
#  
#  2. Redistributions in binary form must reproduce the above copyright notice,
#  this list of conditions and the following disclaimer in the documentation
#  and/or other materials provided with the distribution.
#  
#  3. Neither the name of the copyright holder nor the names of its contributors
#  may be used to endorse or promote products derived from this software without
#  specific prior written permission.
#  
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
#  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
#  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
#  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
#  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
#  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
#  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
#  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from binaryrpc import BinaryRPC


def demo():
    print_hr()
    print("Running demo / tests")
    print_hr()

    proto = "http"
    host = "localhost"
    port = 18081
    daemon = BinaryRPC(proto=proto, host=host, port=port)

    print("Calling: /get_o_indexes.bin")
    txid = "942eaeb8ba05bd13e8d7b85f1599b52a808263419e680d2d1e32ed2f58f6cb78"
    result = daemon.get_o_indexes(txid)
    print("Response indexes:")
    print("  {}".format([e for e in result.o_indexes]))
    print_hr()

    print("Calling: /get_hashes.bin")
    block_ids = ["e865e16b369be945874f75cc4fe3a4a0894ea521f891f2bf8c77ae98a4f4f252",
                 "418015bb9ae982a1975da7d79277c2705727a56894ba0fb246adaabb1f4632e3"]
    start_height = 1738194
    result = daemon.get_hashes(block_ids, start_height)
    print("Response hashes:")
    for e in result.m_block_ids[:3]:
        print("  {}".format(e))
    print("  \033[2m(the first 3 of {})\033[0m".format(result.m_block_ids.count))
    print_hr()

    print("Calling: /get_outs.bin")
    outputs = [(500000000000, 154735)]
    get_txid = True
    result = daemon.get_outs(outputs, get_txid)
    print("Response status:")
    print("  {}".format(result.status));
    print_hr()

    print("Calling: /get_blocks.bin")
    block_ids = ["e865e16b369be945874f75cc4fe3a4a0894ea521f891f2bf8c77ae98a4f4f252",
                 "418015bb9ae982a1975da7d79277c2705727a56894ba0fb246adaabb1f4632e3"]
    start_height = 1738194
    result = daemon.get_blocks(block_ids, start_height)
    print("Response output_indices:")
    txs = result.output_indices.indices[0].indices
    flat = [n for e in txs for n in e]
    for e in flat[:3]:
        print("  {}".format(e))
    print("  \033[2m(the first 3 of {} in first block)\033[0m".format(len(flat)))
    print_hr()

    print("Calling: /get_blocks_by_height.bin")
    heights = [1738194, 1738195]
    result = daemon.get_blocks_by_height(heights)
    print("Response blocks returned:")
    print("  {}".format(result.blocks.count))
    print_hr()

    print("Done!")
    print_hr()


def terminal_size():
    import fcntl, termios, struct
    h, w, hp, wp = struct.unpack("HHHH",
        fcntl.ioctl(0, termios.TIOCGWINSZ,
        struct.pack("HHHH", 0, 0, 0, 0)))
    return w, h


def print_hr():
    columns, rows = terminal_size()
    cols = min(columns, 80)
    print("-" * cols)


if __name__ == "__main__":
    demo()
