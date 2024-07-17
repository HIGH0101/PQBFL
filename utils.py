import ipfs_api
import gzip, io
import os, sys,time, ast
import tarfile, io ,gzip

class MyUtilityClass:
    def __init__(self):
        pass

    def get_from_Ipfs(self, Ipfs_id,client_address):

        Ipfs_data = ipfs_api.http_client.cat(Ipfs_id)
        '''
        with open(f"wrapped_data_{client_address}.tar.gz", "wb") as f:
            f.write(Ipfs_data)
        zipfile =f'wrapped_data_{client_address}.tar.gz' 
        model_file=f'local_model_{client_address}.pth'
        Signature_file=f'signature_{client_address}.bin'
        result=extract_files(zipfile,model_file,Signature_file)

        Model_data=result[model_file]
        open(main_dir +'/server/files/'+model_file,'wb').write(Model_data)
        Signature_data=result[Signature_file]
        open(main_dir +'/server/keys/'+Signature_file,'wb').write(Signature_data)
        '''
        return Ipfs_data

    def upload_to_Ipfs(self, wrapped_data, ETH_address):

        bytes_buffer = io.BytesIO()
        # Write the compressed data to the in-memory buffer
        with gzip.GzipFile(fileobj=bytes_buffer, mode='wb') as gzip_file:
            gzip_file.write(wrapped_data)

        bytes_buffer.seek(0) # Ensure the buffer's position is at the start
        result = ipfs_api.http_client.add(f"wrapped_data_{ETH_address}.tar.gz", recursive=True)   # Upload the zip file to IPFS
        start_index = str(result).find('{')
        end_index = str(result).rfind('}')
        content_inside_braces = str(result)[start_index:end_index + 1]
        result_dict = ast.literal_eval(content_inside_braces)

        return result_dict['Hash']
    
    def analyze_model (self,Local_model,Task_id,project_id_update):
        res=True
        Feedback_score=1
        return res, Feedback_score
    
    def wrapfiles( *files):   # input sample: (('A.bin', A), ('B.enc',B),...)
        tar_buffer = io.BytesIO()  # Create an in-memory TAR archive
        # Create a tarfile object
        with tarfile.open(fileobj=tar_buffer, mode='w') as tar:
            for file_name, file_data in files:
                # Add the file to the archive
                file_info = tarfile.TarInfo(name=file_name)
                file_info.size = len(file_data)
                tar.addfile(file_info, io.BytesIO(file_data))
        
        tar_data = tar_buffer.getvalue()  # Get the TAR archive content as bytes

        return tar_data

    def unwrap_files(tar_data):

        extracted_files = {}
        # Create an in-memory byte stream from the tar_data
        tar_buffer = io.BytesIO(tar_data)

        with tarfile.open(fileobj=tar_buffer, mode='r') as tar:
            # Iterate through the members of the tarfile
            for member in tar.getmembers():
                file = tar.extractfile(member)
                if file is not None:
                    extracted_files[member.name] = file.read()

        return extracted_files

    def unzip(gzip_data):
        with gzip.GzipFile(fileobj=io.BytesIO(gzip_data)) as gz_file:
            tar_data = gz_file.read()
        return tar_data

