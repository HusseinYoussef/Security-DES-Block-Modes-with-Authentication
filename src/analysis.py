import argparse
import time
import matplotlib.pyplot as plt
from tqdm import tqdm
from modes import Crypto

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Analysis')
    parser.add_argument('--mode', type=str, default='ECB',
                        help='name of the selected mode')
    parser.add_argument('--path', type=str, default='Figures',
                        help='path to save the figures')
    args, _ = parser.parse_known_args()

    mode = args.mode
    block_sizes = []

    for i in range(8, 1000, 8):
        block_sizes.append(i)

    for msg_len in tqdm(range(1, 4, 1), desc='Trying different Message length', position=1):
        
        enc_times = []
        for b_size in tqdm(block_sizes, desc='Trying multiple block sizes', position=2):

            msg = ''
            msg = msg.ljust(msg_len*b_size, 'X')

            crypty_obj = Crypto(mode=mode, block_size=b_size)
            start = time.time()
            cipher = crypty_obj.encrypt(msg)
            end = time.time()

            enc_times.append(end-start)

        plt.plot(block_sizes, enc_times)

    plt.xlabel('Block Size (bytes)')
    plt.ylabel('Encryption Time (s)')
    plt.title(f'{mode}')
    plt.legend(['1-block', '2-block', '3-block'])
    # plt.show()
    plt.savefig(f'{args.path}/{mode}.png')