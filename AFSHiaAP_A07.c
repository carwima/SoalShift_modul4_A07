#define FUSE_USE_VERSION 28

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#include<sys/stat.h>
#include<pwd.h>
#include<grp.h>
#include <time.h>
#include <sys/wait.h>
static const char *dirpath = "/home/carwima/shift4/";

char *chiper="qE1~ YMUR2\"`hNIdPzi%^t@(Ao:=CQ,nx4S[7mHFye#aT6+v)DfKL$r?bkOGB>}!9_wV']jcp5JZ&Xl|\\8s;g<{3.u*W-0";

//shift kiri
void decrypt(char* answer)
{
    int i;
    for(i=0; i<strlen(answer); i++){
        char *pch=strchr(chiper, answer[i]);
        if(pch==NULL) continue;
        else
        {   
            if((pch-chiper-17)<0) pch=chiper+((pch-chiper-17+strlen(chiper))%strlen(chiper));
            else pch=chiper+((pch-chiper-17)%strlen(chiper));

            answer[i]=*pch;
        }
    }
    answer[strlen(answer)] = '\0';
}

//shift kanan
void encrypt(char* answer)
{
    int i;
    for(i=0; i<strlen(answer); i++){
        char *pch=strchr(chiper, answer[i]);
        if(pch==NULL) continue;
        else
        {    
            pch=chiper+(pch-chiper+17)%strlen(chiper);

            answer[i]=*pch;
        }
    }
    answer[strlen(answer)] = '\0';
}

void cek_path(char* fpath, char*path){
	if(strcmp(path,"/") == 0)
	{
		sprintf(fpath,"%s",dirpath);
	}	
	else sprintf(fpath,"%s%s",dirpath,path);
}

int cek_file(const char *fpath,const char *filename)
{
	char owner1[] = "chipset";
	char owner2[] = "ic_controller";
	char group1[] = "rusak";
	struct stat status;
	struct passwd *user;
	struct group *group;
	if(stat(fpath,&status) == 0){
        user = getpwuid(status.st_uid);
        group = getgrgid(status.st_gid);
        if((strcmp(user->pw_name,owner1) == 0 || strcmp(user->pw_name,owner2) == 0 ) && strcmp(group->gr_name,group1) == 0 && access(fpath, R_OK) != 0){
		char output_path[1000];
		char filemiris[] = "filemiris.txt";	
		sprintf(output_path,"%s/%s",dirpath,filemiris);
		FILE *output = fopen(output_path,"a");
		fprintf(output,"----------\n");
		fprintf(output,"Filename : %s\n",filename);
		fprintf(output,"GID : %d\n",status.st_gid);
		fprintf(output,"UID : %d\n",status.st_uid);
		fprintf(output,"Acces Time : %s",ctime(&status.st_atime));
		fprintf(output,"----------\n");
		remove(fpath);
		fclose(output);
		return 0;
        }
	}
	return 1;
}

static int xmp_getattr(const char *path, struct stat *stbuf)
{
  	char fpath[1000];
	char enc[1000];
	strcpy(enc,path);
	encrypt(enc);
	cek_path(fpath,enc);

	int res;

	res = lstat(fpath, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		       off_t offset, struct fuse_file_info *fi)
{
	if(strcmp(path,"..")==0 || strcmp(path,".")==0) return 0;
  	char fpath[1000];
	char enc[1000];
	strcpy(enc,path);
	encrypt(enc);
	cek_path(fpath,enc);

	int res = 0;

	DIR *dp;
	struct dirent *de;

	(void) offset;
	(void) fi;

	dp = opendir(fpath);
	if (dp == NULL)
		return -errno;

	while ((de = readdir(dp)) != NULL) {
		if(strcmp(de->d_name,".")!=0 && strcmp(de->d_name,"..")!=0){
			struct stat st;
			char newpath[1000];
			memset(&st, 0, sizeof(st));
			st.st_ino = de->d_ino;
			st.st_mode = de->d_type << 12;
			printf("%s\n",de->d_name);	
			strcpy(newpath,fpath);
			strcat(newpath,"/");
			strcat(newpath,de->d_name);
			if (!cek_file(newpath,de->d_name)) continue;

			decrypt(de->d_name);
			res = (filler(buf, de->d_name, &st, 0));
			if(res!=0) break;

		}
	}
	closedir(dp);
	return 0;
}

static int xmp_read(const char *path, char *buf, size_t size, off_t offset,
		    struct fuse_file_info *fi)
{
  	char fpath[1000];
	char enc[1000];
	strcpy(enc,path);
	encrypt(enc);
	cek_path(fpath,enc);
	int fd;
	int res;

	(void) fi;
	fd = open(fpath, O_RDONLY);
	if (fd == -1)
		return -errno;

	res = pread(fd, buf, size, offset);
	if (res == -1)
		res = -errno;

	close(fd);
	return res;
}

static int xmp_access(const char *path, int mask)
{
  	char fpath[1000];
	char enc[1000];
	strcpy(enc,path);
	encrypt(enc);
	cek_path(fpath,enc);

	int res;

	res = access(fpath, mask);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_readlink(const char *path, char *buf, size_t size)
{
  	char fpath[1000];
	char enc[1000];
	strcpy(enc,path);
	encrypt(enc);
	cek_path(fpath,enc);

	int res;

	res = readlink(fpath, buf, size - 1);
	if (res == -1)
		return -errno;

	buf[res] = '\0';
	return 0;
}




static int xmp_mknod(const char *path, mode_t mode, dev_t rdev)
{
  	char fpath[1000];
	char enc[1000];
	strcpy(enc,path);
	encrypt(enc);
	cek_path(fpath,enc);

	int res;

	// On Linux this could just be 'mknod(path, mode, rdev)' but this is more portable 
	if (S_ISREG(mode)) {
		res = open(fpath, O_CREAT | O_EXCL | O_WRONLY, mode);
		if (res >= 0)
			res = close(res);
	} else if (S_ISFIFO(mode))
		res = mkfifo(fpath, mode);
	else
		res = mknod(fpath, mode, rdev);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_mkdir(const char *path, mode_t mode)
{
	if (strncmp(path,"/YOUTUBER",9) == 0 && strlen(path) != 9) {
			mode = 0750;
	}
  	char fpath[1000];
	char enc[1000];
	strcpy(enc,path);
	encrypt(enc);
	cek_path(fpath,enc);

	int res;

	res = mkdir(fpath, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_unlink(const char *path)
{
  	char fpath[1000];
	char enc[1000];
	strcpy(enc,path);
	encrypt(enc);
	cek_path(fpath,enc);

/*	char bpath[1000];
	char folder[1000]="/Backup/";
	encrypt(folder);
	cek_path(bpath,folder);

	DIR *backup;
	backup =opendir(bpath);

	if (backUp != NULL){	
		char recycle[1000];
		char rpath[1000]="/RecycleBin/";
		encrypt(rpath);
		cek_path(recycle,rpath);
	}
*/
	int res;

	res = unlink(fpath);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_rmdir(const char *path)
{
  	char fpath[1000];
	char enc[1000];
	strcpy(enc,path);
	encrypt(enc);
	cek_path(fpath,enc);
	int res;

	res = rmdir(fpath);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_chmod(const char *path, mode_t mode)
{
	int len = strlen(path);
	const char *ext = &path[len-4];	

	char enc[1000];
  	char fpath[1000];
	strcpy(enc,path);
	encrypt(enc);
	cek_path(fpath,enc);

	struct stat st;
	stat(fpath,&st);
	if (len >= 4 && strcmp(ext,".iz1") == 0 && !S_ISDIR(st.st_mode) && strstr(enc+10,"/")==0) {
		pid_t child_id;
		child_id = fork();
		if (child_id == 0) {
			char *param_alert[] = {"zenity","--error","--title=Error","--text=File ekstensi iz1 tidak boleh diubah permissionnya.\n",NULL};
			execv("/usr/bin/zenity",param_alert);
			return 0;
		}
		return 0;
	}

	int res;


	res = chmod(fpath, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_chown(const char *path, uid_t uid, gid_t gid)
{
  	char fpath[1000];
	char enc[1000];
	strcpy(enc,path);
	encrypt(enc);
	cek_path(fpath,enc);

	int res;

	res = lchown(fpath, uid, gid);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_truncate(const char *path, off_t size)
{
  	char fpath[1000];
	char enc[1000];
	strcpy(enc,path);
	encrypt(enc);
	cek_path(fpath,enc);

	int res;

	res = truncate(fpath, size);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_utimens(const char *path, const struct timespec ts[2])
{
  	char fpath[1000];
	char enc[1000];
	strcpy(enc,path);
	encrypt(enc);
	cek_path(fpath,enc);

	int res;
	struct timeval tv[2];

	tv[0].tv_sec = ts[0].tv_sec;
	tv[0].tv_usec = ts[0].tv_nsec / 1000;
	tv[1].tv_sec = ts[1].tv_sec;
	tv[1].tv_usec = ts[1].tv_nsec / 1000;

	res = utimes(fpath, tv);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_open(const char *path, struct fuse_file_info *fi)
{
  	char fpath[1000];
	char enc[1000];
	strcpy(enc,path);
	encrypt(enc);
	cek_path(fpath,enc);

	int res;

	res = open(fpath, fi->flags);
	if (res == -1)
		return -errno;

	close(res);
	return 0;
}


static int xmp_write(const char *path, const char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi)
{
  	char fpath[1000];
	char enc[1000];

	strcpy(enc,path);
	encrypt(enc);
	cek_path(fpath,enc);


	char folder[1000] = "/Backup";	
	char newpath[1000];	
	encrypt(folder);
	char folderdir[1000];
	cek_path(folderdir,folder);
	mkdir(folderdir,0755);
	
	int fd;
	int res;

	(void) fi;
	fd = open(fpath, O_WRONLY);
	if (fd == -1)
		return -errno;

	res = pwrite(fd, buf, size, offset);
	if (res == -1)
		res = -errno;

	close(fd);

	struct stat sd;
	if(stat(fpath,&sd)>-1 && strstr(path,".swp")==0){
		char t[1000];
		time_t now = time(NULL);
		char fname[1000];
		strftime(t, 22, "_%Y-%m-%d_%H:%M:%S", localtime(&now));
		decrypt(enc);
		sprintf(newpath,"/Backup%s%s.ekstensi",enc,t);
		encrypt(newpath);
		memset(fname,'\0',sizeof(fname));
		sprintf(fname,"%s%s",dirpath,newpath);
		// printf("%s\n",fpath);
		pid_t child1;
		child1=fork();
		if(child1==0){
			execl("/bin/cp","/bin/cp",fpath,fname,NULL);
			return 0;
		}
		else{
			wait(NULL);
		}

		return res;
	}

	return res;
}

static int xmp_statfs(const char *path, struct statvfs *stbuf)
{
  	char fpath[1000];
	char enc[1000];
	strcpy(enc,path);
	encrypt(enc);
	cek_path(fpath,enc);
	int res;

	res = statvfs(fpath, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_create(const char* path, mode_t mode, struct fuse_file_info* fi) 
{    
	char temp[1000];
	strcpy(temp, path);
    
    	if (strstr(temp,"/YOUTUBER")){
		mode = 0640;
		strcat(temp, ".iz1");
	}
  	char fpath[1000];
//	char enc[1000];
//	strcpy(enc,path);
	encrypt(temp);
	cek_path(fpath,temp);

    (void) fi;

    int res;
    res = creat(fpath, mode);
    if(res == -1)
	return -errno;

    close(res);

    return 0;
}


static int xmp_release(const char *path, struct fuse_file_info *fi)
{
  	char fpath[1000];
	char enc[1000];
	strcpy(enc,path);
	encrypt(enc);
	cek_path(fpath,enc);
	// Just a stub.	 This method is optional and can safely be left unimplemented
	
	(void) fpath;
	(void) fi;
	return 0;
}
static int xmp_rename(const char *from, const char *to)
{
  	char ffrom[1000];
	char enc[1000];
	strcpy(enc,ffrom);
	encrypt(enc);
	cek_path(ffrom,enc);

	char fto[1000];
	char enc2[1000];
	strcpy(enc2,fto);
	encrypt(enc2);
	cek_path(fto,enc2);

	int res;

	res = rename(ffrom, fto);
	if (res == -1)
		return -errno;

	return 0;
}




static int xmp_symlink(const char *from, const char *to)
{
  	char ffrom[1000];
	char enc[1000];
	strcpy(enc,ffrom);
	encrypt(enc);
	cek_path(ffrom,enc);

	char fto[1000];
	char enc2[1000];
	strcpy(enc2,fto);
	encrypt(enc2);
	cek_path(fto,enc2);
	
	int res;
	res = symlink(ffrom, fto);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_link(const char *from, const char *to)
{
  	char ffrom[1000];
	char enc[1000];
	strcpy(enc,ffrom);
	encrypt(enc);
	cek_path(ffrom,enc);

	char fto[1000];
	char enc2[1000];
	strcpy(enc2,fto);
	encrypt(enc2);
	cek_path(fto,enc2);

	int res;

	res = link(ffrom, fto);
	if (res == -1)
		return -errno;

	return 0;
}



static struct fuse_operations xmp_oper = {
	.getattr	= xmp_getattr,
	.readdir	= xmp_readdir,
	.read		= xmp_read,
	.access		= xmp_access,
	.readlink	= xmp_readlink,
	.mknod		= xmp_mknod,
	.mkdir		= xmp_mkdir,
	.unlink		= xmp_unlink,
	.rmdir		= xmp_rmdir,
	.chmod		= xmp_chmod,
	.chown		= xmp_chown,
	.truncate	= xmp_truncate,
	.utimens	= xmp_utimens,
	.open		= xmp_open,
	.write		= xmp_write,
	.statfs		= xmp_statfs,
	.create         = xmp_create,
	.release	= xmp_release,
	.rename		= xmp_rename,
//	.fsync		= xmp_fsync,
	.symlink	= xmp_symlink,
	.link		= xmp_link,
 
};

int main(int argc, char *argv[])
{
	umask(0);
	return fuse_main(argc, argv, &xmp_oper, NULL);
}
