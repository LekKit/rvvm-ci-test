/*
rvvd.c - Risc-V Virtual Drive image implementation
Copyright (C) 2022 KotB <github.com/0xCatPKG>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#define RVVD_SECTOR_SIZE 512

#include "rvvd.h"
#include "mem_ops.h"
#include "utils.h"

int rvvd_init(struct rvvd_dev* disk, const char* filename, uint64_t size) {
    // Creates new Risc-V Virtual Drive by filename & size

    rvvm_info("Creating RVVD drive \"%s\" with size %ld", filename, size);

    size_t namelen = strlen(filename);
    if (namelen > 255) namelen = 255;
    memcpy(disk->filename, filename, namelen);
    disk->filename[namelen] = 0;

    disk->overlay = false;
    disk->compression_type = DCOMPESSION_NONE;
    if ( !(disk->_fd = fopen(filename, "wb+")) ) {
        rvvm_error("RVVD ERROR: Could not create drive file!");
        return -1;
    }

    // Writing header
    uint8_t header[512] = {0};
    memcpy(header, "RVVD", 4);
    write_uint32_le(header+4, RVVD_VERSION);
    write_uint64_le(header+8, ((size + 511ULL) & ~511ULL)/512);
    disk->sector_table_size = (size /512 *8 /512);
    disk->size = size;
    disk->version = RVVD_VERSION;
    write_uint64_le(header+16, 512+512*disk->sector_table_size);
    rvvd_sector_write(disk, header, 0);
    disk->next_sector_offset = 512+512*disk->sector_table_size;

    // Allocating sector table
    memset(header, 0, 512);
    for (size_t i=0; i < disk->sector_table_size; ++i) {
        fwrite(header, 512, 1, disk->_fd);
    }

    memset(disk->sector_cache, 0, sizeof(disk->sector_cache));
    disk->sector_cache[0].id = -1;

    return 0;

}

int rvvd_init_overlay(struct rvvd_dev* disk, const char* base_filename, const char* filename){
    // Creates disk in overlay mode, using existing disk image

    rvvm_info("Creating RVVD drive overlay \"%s\" (base drive \"%s\")", filename, base_filename);

    struct rvvd_dev* base_disk = safe_malloc(sizeof(struct rvvd_dev));

    if (rvvd_open(base_disk, base_filename)) {
        rvvm_error("RVVD ERROR: Could not open base drive file!");
        return -1;
    }
    if (rvvd_init(disk, filename, base_disk->size)) {
        rvvm_error("RVVD ERROR: Could not create drive file!");
        return -2;
    }

    rvvm_info("Changing drive type to DTYPE_OVERLAY");

    disk->base_disk = base_disk;
    disk->overlay = true;

    //Seeking in file start pos then modifying default header
    uint8_t header[512] = {0};
    rvvd_sector_read(disk, header, 0);
    write_uint64_le(header+16, 512+512*disk->sector_table_size);
    header[24] |= DOPT_OVERLAY;
    write_uint8(header+25, 0);
    memcpy(header+26, base_disk->filename, 256);

    rvvd_sector_write(disk, header, 0);

    return 0;

}

int rvvd_init_from_image(struct rvvd_dev* disk, const char* image_filename, const char* filename) {
    // Creates disk from passed .img file

    rvvm_info("Creating RVVD drive \"%s\" from \"%s\"", filename, image_filename);

    FILE* img_fd;

    if (!(img_fd = fopen(image_filename, "rb"))) {
        rvvm_error("RVVD ERROR: Could not create drive from image: Can not open image file");
        return -1;
    }

    // Getting file size;
    uint64_t size;
    fseek(img_fd, 0, SEEK_END);
    size = ftell(img_fd);
    fseek(img_fd, 0, SEEK_SET);

    if (rvvd_init(disk, filename, size)) {
        rvvm_error("RVVD ERROR: Could not create drive file!");
        return -2;
    }

    rvvm_info("Writing drive image data to rvvd drive");

    uint8_t bufferspace[512] = {0};
    for (size_t i = 0; i < size/512; i++)
    {
        fread(bufferspace, 512, 1, img_fd);
        rvvd_write(disk, bufferspace, i);
        memset(bufferspace, 0, 512);
    }

    fclose(img_fd);
    return 0;
}

int rvvd_open(struct rvvd_dev* disk, const char* filename) {
    // Opens Risc-V Virtual Drive

    rvvm_info("Opening RVVD drive \"%s\"", filename);

    if ( !(disk->_fd = fopen(filename, "rb+")) ) {
        rvvm_error("RVVD ERROR: Could not open drive file!");
        return -1;
    }

    // Initializing disk structure
    uint8_t header[512] = {0};
    fread(header, 512, 1, disk->_fd);
    if (memcmp(header, "RVVD", 4)) {
        rvvm_error("RVVD ERROR: Passed \"%s\" file is not RVVD drive image.", disk->filename);
        return -2;
    }

    size_t namelen = strlen(filename);
    if (namelen > 255) namelen = 255;
    memcpy(disk->filename, filename, namelen);
    disk->filename[namelen] = 0;

    disk->version = read_uint32_le(header+4);

    if (disk->version != RVVD_VERSION && (disk->version > RVVD_VERSION || disk->version < RVVD_MIN_VERSION)) {
        rvvm_error("RVVD ERROR: version mismatch: can't load newer version of drive image");
        return -3;
    } else if (disk->version != RVVD_VERSION && disk->version < RVVD_VERSION) {
        rvvm_warn("Drive \"%s\" version is outdated, consider update it to new version", disk->filename);
    }

    disk->size = read_uint64_le(header+8)*512;
    disk->next_sector_offset = read_uint64_le(header+16);
    disk->overlay = header[24] & DOPT_OVERLAY;
    disk->compression_type = read_uint8(header+25);
    if (disk->overlay) {

        rvvm_info("Drive \"%s\" is overlay drive, opening base image...", filename);

        struct rvvd_dev* base_disk = safe_malloc(sizeof(struct rvvd_dev));

        // memcpy(base_disk->filename, header+18, 256);
        size_t namelen = strlen((const char*)header+26);
        if (namelen > 255) namelen = 255;
        memcpy(base_disk->filename, header+26, namelen);
        base_disk->filename[namelen] = 0;

        if (!memcmp(base_disk->filename, disk->filename, 256)) {
            rvvm_error("RVVD ERROR: Base drive can not be same as this overlay drive");
            return -4;
        }
        switch (rvvd_open(base_disk, base_disk->filename)) {
            case -1:
                rvvm_error("RVVD ERROR: Can't open drive base.");
                return -4;
            case -2:
                rvvm_error("RVVD ERROR: Can't open drive base: drive base already opened by another instance of rvvm");
                return -4;
            case -3:
                rvvm_error("RVVD ERROR: Can't open drive base: version mismatch: can't load newer version of drive image");
                return -4;
            case -4:
                rvvm_error("RVVD ERROR: Can't open drive base: base drive reported error");
                return -4;
            default:
                disk->base_disk = base_disk;
        }
    }

    disk->sector_table_size = (disk->size /512 *8 /512);
    memset(disk->sector_cache, 0, sizeof(disk->sector_cache));
    disk->sector_cache[0].id = -1;

    return 0;
}

void rvvd_close(struct rvvd_dev* disk) {
    // Closes rvvd disk

    rvvm_info("Closing RVVD drive \"%s\"", disk->filename);

    if (disk->overlay) {
        rvvm_info("Closing RVVM drive base \"%s\"", disk->base_disk->filename);
        rvvd_close(disk->base_disk);
        free(disk->base_disk);
    }

    fclose(disk->_fd);
}

void rvvd_migrate_to_current_version(struct rvvd_dev* disk) {
    // Migrate disk file to the last RVVD version

    uint8_t header[512] = {0};
    rvvd_sector_read(disk, header, 0);
    write_uint32_le(header+4, RVVD_VERSION);
    rvvd_sector_write(disk, header, 0);
}

void rvvd_convert_to_solid(struct rvvd_dev* disk) {
    // Convert overlay image in solid mode

    rvvm_info("RVVD \"%s\": Changing overlay into solid", disk->filename);

    uint8_t buffer[512] = {0};
    for (size_t i = 0; i < disk->sector_table_size*64; i++) {
        rvvd_read(disk, buffer, i);
        rvvd_write(disk, buffer, i);
        memset(buffer, 0, 512);
    }

    rvvd_sector_read(disk, buffer, 0);
    buffer[24] &= ~DOPT_OVERLAY;
    rvvd_sector_write(disk, buffer, 0);
    disk->overlay = false;
    rvvd_sync(disk);

}

void rvvd_dump_to_image(struct rvvd_dev* disk, const char* filename) {
    //Dump contents of RVVD drive into image file

    rvvm_info("RVVD \"%s\": Dumping image", disk->filename);

    FILE* img = fopen(filename, "wb");
    if (img == NULL) {
        rvvm_error("RVVD ERROR at \"%s\": Could not create image file", disk->filename);
    }
    uint8_t buffer[512] = {0};
    for (size_t i = 0; i < disk->sector_table_size*64; i++) {
        rvvd_read(disk, buffer, i);
        fwrite(buffer, 512, 1, img);
        memset(buffer, 0, 512);
    }

    fclose(img);

}

void rvvd_read(struct rvvd_dev* disk, void* buffer, uint64_t sec_id) {

    rvvm_info("RVVD \"%s\": Reading sector %ld", disk->filename, sec_id);

    uint8_t data[512] = {0};

    uint64_t offset = rvvd_sc_get(disk, sec_id);

    if (!offset) offset = rvvd_sector_get_offset(disk, sec_id);

    if (!disk->overlay) {
        if (offset) rvvd_sector_read(disk, data, offset);
    } else {
        if (!offset) rvvd_read(disk->base_disk, data, sec_id);
        else rvvd_sector_read(disk, data, offset);
    }

    memcpy(buffer, data, 512);
    rvvd_sc_push(disk, sec_id, offset);


}

void rvvd_write(struct rvvd_dev* disk, void* data, uint64_t sec_id) {
    /*
    Writing in the disk file. If sector isn't allocated and write data not full of zeros,
    allocates it
    */

    rvvm_info("RVVD \"%s\": Writing sector %ld", disk->filename, sec_id);

    uint64_t offset = rvvd_sc_get(disk, sec_id);

    if (!offset) offset = rvvd_sector_get_offset(disk, sec_id);

    for (size_t i = 0; i < 512/sizeof(size_t); i++) {
        if (((const size_t*)data)[i] && !offset) {
            rvvd_allocate(disk, data, sec_id);
            return;
        }
    }

    if (!offset) return;

    rvvd_sector_write(disk, data, offset);
    rvvd_sc_push(disk, sec_id, offset);

}

void rvvd_allocate(struct rvvd_dev* disk, void* data, uint64_t sec_id) {
    // Allocates block in the disk file

    rvvm_info("RVVD \"%s\": Allocating sector %ld", disk->filename, sec_id);

    uint64_t offset = disk->next_sector_offset;
    disk->next_sector_offset += 512;
    fseek(disk->_fd, offset, SEEK_SET);
    fwrite(data, 512, 1, disk->_fd);

    uint8_t tmpbuf[8] = {0};

    fseek(disk->_fd, 512+sec_id*8, SEEK_SET);
    write_uint64_le(tmpbuf, offset);
    fwrite(tmpbuf, 8, 1, disk->_fd);

    memset(tmpbuf, 0, 8);
    fseek(disk->_fd, 16, SEEK_SET);
    write_uint64_le(tmpbuf, offset);
    fwrite(tmpbuf, 8, 1, disk->_fd);

    rvvd_sc_push(disk, sec_id, offset);

}

void rvvd_sync(struct rvvd_dev* disk) {

    rvvm_info("RVVD \"%s\": Sync request", disk->filename);
    fflush(disk->_fd);
}


void rvvd_sc_push(struct rvvd_dev* disk, uint64_t sec_id, uint64_t offset) {
    // Filling up table conversion result in the sector cache table

    rvvm_info("RVVD \"%s\": Pusing sector cache {%ld : %ld}", disk->filename, sec_id, offset);

    if (offset && disk->sector_cache[sec_id & 0x1FF].id != sec_id) {
        disk->sector_cache[sec_id & 0x1FF].offset = offset;
        disk->sector_cache[sec_id & 0x1FF].id = sec_id;
    }
}

uint64_t rvvd_sc_get(struct rvvd_dev* disk, uint64_t sec_id) {

    rvvm_info("RVVD \"%s\": Getting sector cache entry with sector_id = %ld", disk->filename, sec_id);

    uint64_t offset = 0;
    if (disk->sector_cache[sec_id & 0x1FF].id == sec_id) {
        offset = disk->sector_cache[sec_id & 0x1FF].offset;
    }
    return offset;
}

void rvvd_sc_forward_predict(struct rvvd_dev* disk, uint64_t from_sector, uint32_t sector_count) {

    rvvm_info("RVVD \"%s\": Forward prediction of %d offsets", disk->filename, sector_count);

    if (sector_count > 64) sector_count = 64;
    if (from_sector + sector_count > disk->sector_table_size * 64) return;
    uint8_t buffer[512] = {0};
    fseek(disk->_fd, 512+(8*from_sector), SEEK_SET);
    fread(buffer, 8*sector_count, 1, disk->_fd);
    for (size_t i = 0; i < sector_count; i++) {
        uint64_t offset = read_uint64_le(buffer+(8*i));
        rvvd_sc_push(disk, from_sector+i, offset);
    }
}

uint64_t rvvd_sector_get_offset(struct rvvd_dev* disk, uint64_t sec_id) {
    fseek(disk->_fd, 512+sec_id*8, SEEK_SET);
    uint8_t offsetbuf[8] = {0};
    fread(offsetbuf, 8, 1, disk->_fd);
    return read_uint64_le(offsetbuf);
}

void rvvd_sector_write(struct rvvd_dev* disk, void* data, uint64_t offset) {
    fseek(disk->_fd, offset, SEEK_SET);
    fwrite(data, 512, 1, disk->_fd);
}

void rvvd_sector_read(struct rvvd_dev* disk, void* buffer, uint64_t offset) {
    fseek(disk->_fd, offset, SEEK_SET);
    fread(buffer, 512, 1, disk->_fd);
}

void rvvd_sector_read_recursive(struct rvvd_dev* disk, void* buffer, uint64_t sec_id) {
    rvvd_read(disk, buffer, sec_id);
}
