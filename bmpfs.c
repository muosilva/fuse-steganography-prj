#define FUSE_USE_VERSION 31
#define BMPFS_OPT(t, p) {t, offsetof(struct bmpfs_config, p), 1}

#include <errno.h>
#include <fcntl.h>
#include <fuse3/fuse.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

struct bmpfs_config {
  char *image_path;
};

static struct bmpfs_config config; 

static struct fuse_opt bmpfs_opts[] = {
  BMPFS_OPT("image=%s", image_path), 
  FUSE_OPT_END
};

#pragma pack(push, 1)
typedef struct {
  uint16_t signature;  
  uint32_t filesize;   
  uint16_t reserved1;  
  uint16_t reserved2;  
  uint32_t dataOffset; 
} BMPHeader;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct {
  uint32_t headerSize;      
  int32_t width;            
  int32_t height;           
  uint16_t planes;          
  uint16_t bitsPerPixel;    
  uint32_t compression;     
  uint32_t imageSize;       
  int32_t xPixelsPerM;      
  int32_t yPixelsPerM;      
  uint32_t colorsUsed;      
  uint32_t colorsImportant; 
} BMPInfoHeader;
#pragma pack(pop)


typedef struct {
  char filename[256];
  size_t size;
  time_t created;
  time_t modified;
  time_t accessed;      
  uint32_t first_block; 
  uint32_t num_blocks;  
  mode_t mode;          
  uid_t uid;            
  gid_t gid;            
} FileMetadata;


typedef struct {
  FILE *bmp_file;
  BMPHeader header;
  BMPInfoHeader info_header;
  size_t data_size;    
  size_t block_size;   
  uint8_t *bitmap;     
  FileMetadata *files; 
  size_t max_files;    
  char *image_path;    
} bmp_fs_state;

static bmp_fs_state fs_state;

static size_t meta_size_calc(bmp_fs_state *state) {
  size_t total_blocks = state->data_size / state->block_size;
  size_t bitmap_size = total_blocks; 
  size_t file_metadata_size = state->max_files * sizeof(FileMetadata);
  return bitmap_size + file_metadata_size;
}

static int meta_read(bmp_fs_state *state) {
  size_t metadata_size = meta_size_calc(state);
  char *buffer = malloc(metadata_size);
  if (!buffer) {
    return -ENOMEM;
  }

  if (fseek(state->bmp_file, state->header.dataOffset, SEEK_SET) != 0) {
    free(buffer);
    return -EIO;
  }

  size_t read_bytes = fread(buffer, 1, metadata_size, state->bmp_file);
  if (read_bytes != metadata_size) {
    free(buffer);
    return -EIO;
  }

  size_t bitmap_size = state->data_size / state->block_size;
  memcpy(state->bitmap, buffer, bitmap_size);
  memcpy(state->files, buffer + bitmap_size,
         state->max_files * sizeof(FileMetadata));

  free(buffer);
  return 0;
}

static int meta_write(bmp_fs_state *state) {
  size_t metadata_size = meta_size_calc(state);
  char *buffer = malloc(metadata_size);
  if (!buffer) {
    return -ENOMEM;
  }

  size_t bitmap_size = state->data_size / state->block_size;
  memcpy(buffer, state->bitmap, bitmap_size);
  memcpy(buffer + bitmap_size, state->files,
         state->max_files * sizeof(FileMetadata));

  if (fseek(state->bmp_file, state->header.dataOffset, SEEK_SET) != 0) {
    free(buffer);
    return -EIO;
  }

  size_t written = fwrite(buffer, 1, metadata_size, state->bmp_file);
  if (written != metadata_size) {
    free(buffer);
    return -EIO;
  }

  if (fflush(state->bmp_file) != 0) {
    free(buffer);
    return -EIO;
  }

  free(buffer);
  return 0;
}

static int create_bmp_file(const char *filename, size_t width, size_t height) {

  char *dir_path = strdup(filename);
  char *last_slash = strrchr(dir_path, '/');
  if (last_slash) {
    *last_slash = '\0';
  } else {
    dir_path[0] = '.';
    dir_path[1] = '\0';
  }

  if (access(dir_path, W_OK) != 0) {
    free(dir_path);
    return -errno;
  }
  free(dir_path);

  if (access(filename, F_OK) == 0) {

    if (access(filename, W_OK) != 0) {
      return -errno;
    }
    return 0;
  }

  int fd = open(filename, O_WRONLY | O_CREAT, 0644);
  if (fd == -1) {
    return -errno;
  }
  FILE *fp = fdopen(fd, "wb");
  if (!fp) {
    close(fd);
    return -errno;
  }

  size_t pixel_data_size;
  if (__builtin_mul_overflow(width * height, 3, &pixel_data_size)) {
    fclose(fp);
    return -EOVERFLOW;
  }

  size_t file_size;
  if (__builtin_add_overflow(sizeof(BMPHeader) + sizeof(BMPInfoHeader),
                             pixel_data_size, &file_size)) {
    fclose(fp);
    return -EOVERFLOW;
  }

  BMPHeader header = {.signature = 0x4D42,
                      .filesize = file_size,
                      .reserved1 = 0,
                      .reserved2 = 0,
                      .dataOffset = sizeof(BMPHeader) + sizeof(BMPInfoHeader)};

  BMPInfoHeader info_header = {.headerSize = sizeof(BMPInfoHeader),
                               .width = width,
                               .height = height,
                               .planes = 1,
                               .bitsPerPixel = 24,
                               .compression = 0,
                               .imageSize = pixel_data_size,
                               .xPixelsPerM = 2835,
                               .yPixelsPerM = 2835,
                               .colorsUsed = 0,
                               .colorsImportant = 0};

  if (fwrite(&header, sizeof(BMPHeader), 1, fp) != 1 || fwrite(&info_header, sizeof(BMPInfoHeader), 1, fp) != 1) {
    fclose(fp);
    return -errno;
  }

  unsigned char *pixel_data = calloc(1, pixel_data_size);
  if (!pixel_data) {
    fclose(fp);
    return -ENOMEM;
  }

  size_t written = fwrite(pixel_data, 1, pixel_data_size, fp);
  free(pixel_data);

  if (written != pixel_data_size) {
    fclose(fp);
    return -errno;
  }

  size_t total_blocks = pixel_data_size / 512;
  size_t bitmap_size = total_blocks;
  size_t files_size = 1000 * sizeof(FileMetadata);
  size_t metadata_size = bitmap_size + files_size;

  char *initial_metadata = calloc(1, metadata_size);
  if (!initial_metadata) {
    fclose(fp);
    return -ENOMEM;
  }

  if (fseek(fp, header.dataOffset, SEEK_SET) != 0) {
    free(initial_metadata);
    fclose(fp);
    return -EIO;
  }

  size_t metadata_written = fwrite(initial_metadata, 1, metadata_size, fp);
  free(initial_metadata);

  if (metadata_written != metadata_size) {
    fclose(fp);
    return -EIO;
  }

  if (fflush(fp) != 0) {
    fclose(fp);
    return -EIO;
  }

  return 0;
}

static int path_validator(const char *path) {
  if (!path || strlen(path) >= 256) {
    return -ENAMETOOLONG;
  }

  if (path[0] == '/') {
    path++;
  }

  const char *invalid = strchr(path, '/');
  if (invalid) {
    return -EINVAL;
  }

  return 0;
}

static int path_to_meta(const char *path) {
  int validation = path_validator(path);
  if (validation < 0) {
    return validation;
  }

  if (path[0] == '/') {
    path++;
  }

  for (size_t i = 0; i < fs_state.max_files; i++) {
    if (fs_state.files[i].filename[0] != '\0' &&
        strcmp(fs_state.files[i].filename, path) == 0) {
      return i;
    }
  }
  return -ENOENT;
}

static uint32_t find_free_blocks(size_t num_blocks) {
  if (num_blocks == 0) {
    return 0;
  }

  size_t total_blocks = fs_state.data_size / fs_state.block_size;
  size_t consecutive = 0;
  uint32_t start_block = 0;

  for (size_t i = 0; i < total_blocks; i++) {
    if (fs_state.bitmap[i] == 0) {
      if (consecutive == 0) {
        start_block = i;
      }
      consecutive++;
      if (consecutive >= num_blocks) {
        return start_block;
      }
    } else {
      consecutive = 0;
    }
  }
  return UINT32_MAX;
}

static int block_reader(uint32_t start_block, size_t num_blocks, char *buffer) {
  if (!buffer || !fs_state.bmp_file) {
    return -EINVAL;
  }

  size_t metadata_size = meta_size_calc(&fs_state);
  size_t offset = fs_state.header.dataOffset + metadata_size +
                  (start_block * fs_state.block_size);
  if (fseek(fs_state.bmp_file, offset, SEEK_SET) != 0) {
    return -EIO;
  }

  size_t bytes_read =
      fread(buffer, 1, fs_state.block_size * num_blocks, fs_state.bmp_file);
  if (bytes_read != fs_state.block_size * num_blocks) {
    return -EIO;
  }

  return 0;
}

static int block_writer(uint32_t start_block, size_t num_blocks, const char *buffer) {
  if (!buffer || !fs_state.bmp_file) {
    return -EINVAL;
  }

  size_t metadata_size = meta_size_calc(&fs_state);
  size_t offset = fs_state.header.dataOffset + metadata_size + (start_block * fs_state.block_size);

  if (fseek(fs_state.bmp_file, offset, SEEK_SET) != 0) {
    return -EIO;
  }

  size_t bytes_written = fwrite(buffer, 1, fs_state.block_size * num_blocks, fs_state.bmp_file);

  if (bytes_written != fs_state.block_size * num_blocks) {
    return -EIO;
  }

  if (fflush(fs_state.bmp_file) != 0) {
    return -EIO;
  }

  return 0;
}

static int bmpfs_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi) {
  memset(stbuf, 0, sizeof(struct stat));

  if (strcmp(path, "/") == 0) {
    stbuf->st_mode = S_IFDIR | 0755;
    stbuf->st_nlink = 2;
    stbuf->st_uid = getuid();
    stbuf->st_gid = getgid();
    stbuf->st_atime = time(NULL);
    stbuf->st_mtime = stbuf->st_atime;
    stbuf->st_ctime = stbuf->st_atime;
    return 0;
  }

  int idx = path_to_meta(path);

  if (idx < 0) {
    return idx;
  }

  FileMetadata *meta = &fs_state.files[idx];
  stbuf->st_mode = meta->mode;
  stbuf->st_nlink = 1;
  stbuf->st_size = meta->size;
  stbuf->st_uid = meta->uid;
  stbuf->st_gid = meta->gid;
  stbuf->st_atime = meta->accessed;
  stbuf->st_mtime = meta->modified;
  stbuf->st_ctime = meta->created;
  stbuf->st_blocks = (meta->size + 511) / 512; 
  stbuf->st_blksize = fs_state.block_size;

  return 0;
}

static int bmpfs_creator(const char *path, mode_t mode, struct fuse_file_info *fi) {
  int validation = path_validator(path);

  if (validation < 0) {
    
    return validation;
  }

  if (path_to_meta(path) >= 0) {
    
    return -EEXIST;
  }

  int idx = -1;

  for (size_t i = 0; i < fs_state.max_files; i++) {
    if (fs_state.files[i].filename[0] == '\0') {
      idx = i;
      break;
    }
  }

  if (idx < 0) {
    return -ENOMEM;
  }

  FileMetadata *meta = &fs_state.files[idx];
  const char *filename = path;
  if (path[0] == '/') {
    filename++;
  }

  strncpy(meta->filename, filename, sizeof(meta->filename) - 1);
  meta->filename[sizeof(meta->filename) - 1] = '\0';
  meta->size = 0;
  meta->created = time(NULL);
  meta->modified = meta->created;
  meta->accessed = meta->created;
  meta->first_block = UINT32_MAX; 
  meta->num_blocks = 0;
  meta->mode = S_IFREG | (mode & 0777);
  meta->uid = getuid();
  meta->gid = getgid();

  if (meta_write(&fs_state) < 0) {
    return -EIO;
  }

  return 0;
}

static void *bmpfs_init(struct fuse_conn_info *conn, struct fuse_config *cfg) {
  cfg->kernel_cache = 1;
  cfg->entry_timeout = 60.0;
  cfg->attr_timeout = 60.0;

  if (!fs_state.image_path) {
    return NULL;
  }


  fs_state.bmp_file = fopen(fs_state.image_path, "r+b");
  if (!fs_state.bmp_file) {
    int create_result = create_bmp_file(fs_state.image_path, 2048, 2048);

    if (create_result < 0) {
      return NULL;
    }

    fs_state.bmp_file = fopen(fs_state.image_path, "r+b");
    if (!fs_state.bmp_file) {
      return NULL;
    }
  }

  int fd = fileno(fs_state.bmp_file);
  if (fd == -1) {
    fclose(fs_state.bmp_file);
    return NULL;
  }

  struct stat st;
  if (fstat(fd, &st) == -1) {
    fclose(fs_state.bmp_file);
    return NULL;
  }

  if ((st.st_mode & S_IRUSR) == 0 || (st.st_mode & S_IWUSR) == 0) {
    fclose(fs_state.bmp_file);
    return NULL;
  }

  BMPHeader header;
  BMPInfoHeader info_header;

  if (fread(&header, sizeof(BMPHeader), 1, fs_state.bmp_file) != 1) {
    fclose(fs_state.bmp_file);
    return NULL;
  }

  if (header.signature != 0x4D42) {
    fclose(fs_state.bmp_file);
    return NULL;
  }

  if (fread(&info_header, sizeof(BMPInfoHeader), 1, fs_state.bmp_file) != 1) {
    fclose(fs_state.bmp_file);
    return NULL;
  }

  fs_state.header = header;
  fs_state.info_header = info_header;
  fs_state.data_size = info_header.imageSize;
  fs_state.block_size = 512;
  fs_state.max_files = 1000;

  size_t bitmap_size = fs_state.data_size / fs_state.block_size;
  fs_state.bitmap = calloc(bitmap_size, sizeof(uint8_t));

  if (!fs_state.bitmap) {
    fclose(fs_state.bmp_file);
    return NULL;
  }

  fs_state.files = calloc(fs_state.max_files, sizeof(FileMetadata));
  if (!fs_state.files) {
    free(fs_state.bitmap);
    fclose(fs_state.bmp_file);
    return NULL;
  }

  if (meta_read(&fs_state) < 0) {
    free(fs_state.bitmap);
    free(fs_state.files);
    fclose(fs_state.bmp_file);
    return NULL;
  }

  return &fs_state;
}

static void bmpfs_destroyer(void *private_data) {
  if (fs_state.bmp_file) {
    fclose(fs_state.bmp_file);
    fs_state.bmp_file = NULL;
  }

  free(fs_state.bitmap);
  fs_state.bitmap = NULL;
  free(fs_state.files);
  fs_state.files = NULL;
  free(fs_state.image_path);
  fs_state.image_path = NULL;
}

static int bmpfs_unlink(const char *path) {
  int idx = path_to_meta(path);
  
  if (idx < 0) {
    return idx;
  }

  FileMetadata *meta = &fs_state.files[idx];

  for (uint32_t i = 0; i < meta->num_blocks; i++) {
    fs_state.bitmap[meta->first_block + i] = 0;
  }


  memset(meta, 0, sizeof(FileMetadata));

  if (meta_write(&fs_state) < 0) {
    return -EIO;
  }

  return 0;
}

static int bmpfs_reader(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
  if (!buf) {
    return -EINVAL;
  }

  int idx = path_to_meta(path);
  if (idx < 0) {
    return idx;
  }

  FileMetadata *meta = &fs_state.files[idx];

  meta->accessed = time(NULL);

  if (offset >= meta->size) {
    return 0;
  }

  if (offset + size > meta->size) {
    size = meta->size - offset;
  }


  uint32_t start_block = meta->first_block + (offset / fs_state.block_size);
  size_t block_offset = offset % fs_state.block_size;
  size_t blocks_to_read = (size + block_offset + fs_state.block_size - 1) / fs_state.block_size;

  char *temp_buf = malloc(blocks_to_read * fs_state.block_size);
  if (!temp_buf) {
    return -ENOMEM;
  }

  int read_result = block_reader(start_block, blocks_to_read, temp_buf);
  if (read_result < 0) {
    free(temp_buf);
    return read_result;
  }

  memcpy(buf, temp_buf + block_offset, size);
  free(temp_buf);

  return size;
}

static int bmpfs_writer(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
  if (!buf) {
    return -EINVAL;
  }

  int idx = path_to_meta(path);

  if (idx < 0) {
    return idx;
  }

  FileMetadata *meta = &fs_state.files[idx];
  size_t new_size = offset + size;

  if (new_size < offset) {
    return -EFBIG;
  }

  size_t new_blocks = (new_size + fs_state.block_size - 1) / fs_state.block_size;

  if (new_blocks > meta->num_blocks) {
    uint32_t new_start = find_free_blocks(new_blocks);
    if (new_start == UINT32_MAX) {
      
      return -ENOSPC;
    }

    
    if (meta->num_blocks > 0) {
      char *temp_buf = malloc(meta->num_blocks * fs_state.block_size);
      if (!temp_buf) {
        
        return -ENOMEM;
      }

      int read_result =
          block_reader(meta->first_block, meta->num_blocks, temp_buf);
      if (read_result < 0) {
        
        free(temp_buf);
        return read_result;
      }

      int write_result = block_writer(new_start, meta->num_blocks, temp_buf);
      free(temp_buf);

      if (write_result < 0) {
        
        return write_result;
      }

      
      for (uint32_t i = 0; i < meta->num_blocks; i++) {
        fs_state.bitmap[meta->first_block + i] = 0;
      }
    }

    
    meta->first_block = new_start;
    for (uint32_t i = 0; i < new_blocks; i++) {
      fs_state.bitmap[new_start + i] = 1;
    }
    meta->num_blocks = new_blocks;
  }

  
  uint32_t start_block = meta->first_block + (offset / fs_state.block_size);
  size_t block_offset = offset % fs_state.block_size;
  size_t blocks_to_write =
      (size + block_offset + fs_state.block_size - 1) / fs_state.block_size;

  char *temp_buf = malloc(blocks_to_write * fs_state.block_size);
  if (!temp_buf) {
    
    return -ENOMEM;
  }

  
  if (block_offset > 0 || (size % fs_state.block_size) != 0) {
    int read_result = block_reader(start_block, blocks_to_write, temp_buf);
    if (read_result < 0) {
      
      free(temp_buf);
      return read_result;
    }
  }

  
  memcpy(temp_buf + block_offset, buf, size);

  
  int write_result = block_writer(start_block, blocks_to_write, temp_buf);
  free(temp_buf);

  if (write_result < 0) {
    
    return write_result;
  }

  
  if (new_size > meta->size) {
    meta->size = new_size;
  }
  meta->modified = time(NULL);

  

  
  if (meta_write(&fs_state) < 0) {
    
    return -EIO;
  }

  return size;
}

static int bmpfs_directory_reader(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi, enum fuse_readdir_flags flags) {
  if (strcmp(path, "/") != 0) {
    return -ENOENT;
  }
  
  if (filler(buf, ".", NULL, 0, 0) || filler(buf, "..", NULL, 0, 0)) {
    return -ENOMEM;
  }
  
  for (size_t i = 0; i < fs_state.max_files; i++) {
    if (fs_state.files[i].filename[0] != '\0') {
      struct stat st;
      memset(&st, 0, sizeof(struct stat));
      st.st_mode = fs_state.files[i].mode;
      st.st_nlink = 1; 
      st.st_size = fs_state.files[i].size;
      st.st_uid = fs_state.files[i].uid;
      st.st_gid = fs_state.files[i].gid;
      st.st_atime = fs_state.files[i].accessed;
      st.st_mtime = fs_state.files[i].modified;
      st.st_ctime = fs_state.files[i].created;
      st.st_blocks =
          (fs_state.files[i].size + 511) / 512; 
      st.st_blksize = fs_state.block_size;

      if (filler(buf, fs_state.files[i].filename, &st, 0, 0)) {
        return -ENOMEM;
      }
    }
  }

  return 0;
}

static int bmpfs_truncate(const char *path, off_t size, struct fuse_file_info *fi) {
  if (size < 0) {
    return -EINVAL;
  }

  int idx = path_to_meta(path);
  if (idx < 0) {
    return idx;
  }

  FileMetadata *meta = &fs_state.files[idx];

  
  size_t new_blocks = (size + fs_state.block_size - 1) / fs_state.block_size;

  
  if (size == 0) {
    for (uint32_t i = 0; i < meta->num_blocks; i++) {
      fs_state.bitmap[meta->first_block + i] = 0;
    }
    meta->first_block = UINT32_MAX;
    meta->num_blocks = 0;
    meta->size = 0;
    meta->modified = time(NULL);
  }
  
  else if (new_blocks < meta->num_blocks) {
    for (uint32_t i = new_blocks; i < meta->num_blocks; i++) {
      fs_state.bitmap[meta->first_block + i] = 0;
    }
    meta->num_blocks = new_blocks;
    meta->size = size;
    meta->modified = time(NULL);
  }
  
  else if (new_blocks > meta->num_blocks) {
    uint32_t new_start = find_free_blocks(new_blocks);
    if (new_start == UINT32_MAX) {
      return -ENOSPC;
    }

    
    if (meta->num_blocks > 0) {
      char *temp_buf = malloc(meta->num_blocks * fs_state.block_size);

      if (!temp_buf) {
        return -ENOMEM;
      }

      int read_result = block_reader(meta->first_block, meta->num_blocks, temp_buf);

      if (read_result < 0) {
        free(temp_buf);
        return read_result;
      }

      int write_result = block_writer(new_start, meta->num_blocks, temp_buf);
      free(temp_buf);

      if (write_result < 0) {
        return write_result;
      }

      
      for (uint32_t i = 0; i < meta->num_blocks; i++) {
        fs_state.bitmap[meta->first_block + i] = 0;
      }
    }

    
    for (uint32_t i = 0; i < new_blocks; i++) {
      fs_state.bitmap[new_start + i] = 1;
    }

    meta->first_block = new_start;
    meta->num_blocks = new_blocks;
    meta->size = size;
    meta->modified = time(NULL);
  }

  
  if (meta_write(&fs_state) < 0) {
    
    return -EIO;
  }

  return 0;
}

static int bmpfs_utimens(const char *path, const struct timespec ts[2], struct fuse_file_info *fi) {
  int idx = path_to_meta(path);
  if (idx < 0) {
    return idx;
  }

  FileMetadata *meta = &fs_state.files[idx];

  
  if (ts) {
    meta->accessed = ts[0].tv_sec;
    meta->modified = ts[1].tv_sec;
  } else {
    time_t current = time(NULL);
    meta->accessed = current;
    meta->modified = current;
  }

  return 0;
}

static int bmpfs_fsync(const char *path, int datasync, struct fuse_file_info *fi) {
  if (!fs_state.bmp_file) {
    return -EIO;
  }

  if (datasync) {
    return fdatasync(fileno(fs_state.bmp_file));
  } else {
    return fsync(fileno(fs_state.bmp_file));
  }
}

static int bmpfs_open(const char *path, struct fuse_file_info *fi) {
  int idx = path_to_meta(path);

  if (idx < 0) {
    return idx; 
  }

  FileMetadata *meta = &fs_state.files[idx];

  
  if ((fi->flags & O_WRONLY) && !(meta->mode & S_IWUSR)) {
    return -EACCES; 
  }
  if ((fi->flags & O_RDONLY) && !(meta->mode & S_IRUSR)) {
    return -EACCES; 
  }

  
  meta->accessed = time(NULL);

  return 0; 
}

static const struct fuse_operations bmpfs_ops = {
    .init = bmpfs_init,
    .destroy = bmpfs_destroyer,
    .getattr = bmpfs_getattr,
    .readdir = bmpfs_directory_reader,
    .create = bmpfs_creator,
    .unlink = bmpfs_unlink,
    .read = bmpfs_reader,
    .write = bmpfs_writer,
    .open = bmpfs_open,
    .truncate = bmpfs_truncate,
    .utimens = bmpfs_utimens,
    .fsync = bmpfs_fsync,
};

int main(int argc, char *argv[]) {
  struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

  config.image_path = NULL;

  if (fuse_opt_parse(&args, &config, bmpfs_opts, NULL) == -1) {
    return 1;
  }
  
  if (config.image_path == NULL) {
    fprintf(stderr, "CMD: %s {your-folder} -o image={image_file.bmp>}\n", argv[0]);
    fuse_opt_free_args(&args);
    return 1;
  }

  fs_state.image_path = strdup(config.image_path);
  if (!fs_state.image_path) {
    fprintf(stderr, "Failed to allocate memory for image path\n");
    fuse_opt_free_args(&args);
    return 1;
  }

  int ret = fuse_main(args.argc, args.argv, &bmpfs_ops, NULL);
  fuse_opt_free_args(&args);

  return ret;
}
