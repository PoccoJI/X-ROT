project('X-ROT', 'c')

inc = include_directories('src/include')

executable('main', 'src/main.c', include_directories: inc)

executable('sha256_test', 'test/sha256_test.c','src/crypto/sha256.c', include_directories: inc)
executable('aes_test', 'test/aes_test.c','src/crypto/aes.c', include_directories: inc)
