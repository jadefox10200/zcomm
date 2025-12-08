/**
 * Custom upload adapter for CKEditor 5
 * Handles image uploads to the server via /api/upload endpoint
 * 
 * Note: Uses 'any' types for CKEditor loader and editor as these are internal
 * CKEditor types that are not properly exported in the build-classic package.
 */

// Use the same base URL as the rest of the API, but construct the full upload URL
const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8080/api';
const UPLOAD_URL = `${API_BASE_URL}/upload`;

class UploadAdapter {
  private loader: any; // CKEditor FileLoader - type not exported
  private xhr: XMLHttpRequest | null = null;

  constructor(loader: any) {
    this.loader = loader;
  }

  upload(): Promise<{ default: string }> {
    return this.loader.file.then(
      (file: File) =>
        new Promise((resolve, reject) => {
          this._initRequest();
          this._initListeners(resolve, reject, file);
          this._sendRequest(file);
        })
    );
  }

  abort() {
    if (this.xhr) {
      this.xhr.abort();
    }
  }

  private _initRequest() {
    const xhr = (this.xhr = new XMLHttpRequest());
    // Upload to the configured backend URL
    xhr.open("POST", UPLOAD_URL, true);
    xhr.responseType = "json";
  }

  private _initListeners(
    resolve: (value: { default: string }) => void,
    reject: (reason?: any) => void,
    file: File
  ) {
    const xhr = this.xhr!;
    const loader = this.loader;
    const genericErrorText = `Couldn't upload file: ${file.name}.`;

    xhr.addEventListener("error", () => reject(genericErrorText));
    xhr.addEventListener("abort", () => reject());
    xhr.addEventListener("load", () => {
      const response = xhr.response;

      if (!response || response.error) {
        return reject(
          response && response.error ? response.error.message : genericErrorText
        );
      }

      // Expected response format: { url: "http://example.com/uploaded-image.jpg" }
      resolve({
        default: response.url,
      });
    });

    if (xhr.upload) {
      xhr.upload.addEventListener("progress", (evt: ProgressEvent) => {
        if (evt.lengthComputable) {
          loader.uploadTotal = evt.total;
          loader.uploaded = evt.loaded;
        }
      });
    }
  }

  private _sendRequest(file: File) {
    const data = new FormData();
    data.append("upload", file);
    this.xhr!.send(data);
  }
}

/**
 * Plugin function to add the custom upload adapter to CKEditor
 * Usage: Add this to CKEditor config:
 * config={{
 *   extraPlugins: [uploadPlugin],
 *   ...
 * }}
 * 
 * @param editor - CKEditor ClassicEditor instance (type not exported from build-classic)
 */
export function uploadPlugin(editor: any) {
  editor.plugins.get("FileRepository").createUploadAdapter = (loader: any) => {
    return new UploadAdapter(loader);
  };
}
