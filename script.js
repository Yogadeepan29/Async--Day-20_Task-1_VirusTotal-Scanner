//! <--------------------------------------- Getting DOM elements --------------------------------------->
const fileInput = document.getElementById("fileInput");
const scanFile = document.getElementById("scanFile");
const urlInput = document.getElementById("urlInput");
const scanUrl = document.getElementById("scanUrl");
const fileInfo = document.getElementById("file-info");
const urlInfo = document.getElementById("url-info");
const resultSection = document.getElementById("result");
const hashOutput = document.getElementById("hashValue");
const date = document.getElementById("date");
const details = document.getElementById("details");
const iframeContainer = document.getElementById("iframe-container");
const widget = document.getElementById("widget");

//* <-------------------------------------------- VirusTotal API key -------------------------------------------->
const apiKey =
  "8ae96d3233eba5915e177ed3a370b38b4f18091acbd1a8a7a044f3e20378e49f";

//! <---------------------------------------- Event listener for scanning a file ---------------------------------------->

scanFile.addEventListener("click", (upload) => {
  upload.preventDefault();
  iframeContainer.innerHTML = "";
  hashOutput.innerHTML = `<div class="d-flex justify-content-center">
  <div class="spinner-border text-info" role="status">
    <span class="visually-hidden">Loading...</span>
  </div>
</div>`;
  date.innerHTML = "";
  details.innerHTML = "";
  const file = fileInput.files[0];
  //* <---------------------------------------- Validation ---------------------------------------->
  if (!file) {
    fileInfo.textContent = "Please select a file to scan (Max - 32MB)";
    fileInput.className += " is-invalid";
    hashOutput.innerHTML = "";
    return;
  } else if (file.size > 32 * 1024 * 1024) {
    fileInfo.textContent = "File is Too Large (Max - 32MB)";
    fileInput.className += " is-invalid";
    hashOutput.innerHTML = "";
    return;
  } else {
    fileInfo.textContent = "";
    fileInput.className = fileInput.className.replace(" is-invalid", "");
  }

  const formData = new FormData();
  formData.append("file", file);

  //* <------------------------------------------ API Call ------------------------------------------>

  const getFile = {
    method: "POST",
    headers: {
      accept: "application/json",
      "x-apikey": apiKey,
    },
    body: formData,
  };

  fetch("https://cors-anywhere.herokuapp.com/https://www.virustotal.com/api/v3/files", getFile)
    .then((response) => {
      if (!response.ok) {
        return response.json().then((error) => {
          throw new Error(`${response.status}: ${error.error.message}`);
        });
      }
      return response.json();
    })
    .then((data) => {
      // console.log(data);
      if (!data.data || !data.data.id) {
        throw new Error("Invalid response from file submission");
      }
      const fileId = data.data.id;
      //* <------------------------ Rerouted for in-depth analysis to access detailed information ------------------------>
      return fetch(`https://cors-anywhere.herokuapp.com/https://www.virustotal.com/api/v3/analyses/${fileId}`, {
        method: "GET",
        headers: {
          accept: "application/json",
          "x-apikey": apiKey,
        },
      });
    })
    .then((response) => {
      if (!response.ok) {
        return response.json().then((error) => {
          throw new Error(`${response.status}: ${error.error.message}`);
        });
      }
      return response.json();
    })
    .then((data) => {
      // console.log(data);
      if (!data.meta || !data.meta.file_info) {
        throw new Error("Invalid response from analysis");
      }
      const sha256 = data.meta.file_info.sha256;
      const time = data.data.attributes.date;
      const dateObject = new Date(time * 1000);
      const formattedDate = dateObject.toLocaleString();
      //* <-------------------------- appends last scan date and sha-256 values to the webpage -------------------------->
      hashOutput.innerHTML = `<b>SHA-256 :</b> ${sha256}`;
      date.innerHTML = `<b>Last Scanned :</b> ${formattedDate} <br>`;
      details.innerHTML = `<a href="https://www.virustotal.com/gui/file/${sha256}" target="_blank">
                            <button type="button" class="btn btn-success mb-2">View Detailed Report</button></a>
                             <p class="text-success fw-bold">Note : Recommended to View Detailed Report for more information. </p>
                              <p class="text-danger fw-bolder"> If No VirusTotal reports available for this item use Detailed Report.</p>`;

      //* <------------------------------ Rerouted to get widget report of the scanned file ------------------------------>
      return fetch(
        `https://cors-anywhere.herokuapp.com/https://www.virustotal.com/api/v3/widget/url?query=${sha256}`,
        {
          method: "GET",
          headers: {
            accept: "application/json",
            "x-apikey": apiKey,
          },
        }
      )
        .then((response) => {
          if (!response.ok) {
            return response.json().then((error) => {
              throw new Error(`${response.status}: ${error.error.message}`);
            });
          }
          return response.json();
        })
        .then((data) => {
          // console.log(data);
          if (!data.data || !data.data.url) {
            throw new Error("Invalid response from widget request");
          }
          const url = data.data.url;
          //* <------------------------------- insert widget to the webpage ------------------------------->
          widget.src = url;
          iframeContainer.className = iframeContainer.className.replace(
            "d-none",
            "d-block"
          );
          iframeContainer.appendChild(widget);
        });
    })
    //* <----------------------------------------- Error Handling --------------------------------------------->
    .catch((error) => {
      console.log("Error : ", error.message);
      fileInfo.textContent = `Error: ${error.message || error}`;
      fileInput.className += " is-invalid";
      hashOutput.innerHTML = "";
    });
});

//! <------------------------------------------- Event listener for scanning a URL ------------------------------------------->

scanUrl.addEventListener("click", (upload) => {
  upload.preventDefault();
  iframeContainer.innerHTML = "";
  hashOutput.innerHTML = `<div class="d-flex justify-content-center">
  <div class="spinner-border text-info" role="status">
    <span class="visually-hidden">Loading...</span>
  </div>
</div>`;
  date.innerHTML = "";
  details.innerHTML = "";

  const url = urlInput.value;

  const urlPattern =
    /\b(?:(?:https?|ftp):\/\/|www\.)[-a-zA-Z0-9+&@#\/%?=~_|!:,.;]*\.[a-zA-Z]{1,}[-a-zA-Z0-9+&@#\/%=~_|]/;
  //* <--------------------------------------------------- Validation --------------------------------------------------->
  if (!urlInput.value) {
    urlInfo.textContent = "Please enter a URL to scan";
    urlInput.className += " is-invalid";
    hashOutput.innerHTML = "";
    return;
  } else if (!urlPattern.test(url)) {
    urlInfo.textContent = "Invalid URL";
    urlInput.className += " is-invalid";
    hashOutput.innerHTML = "";
    return;
  } else {
    urlInfo.textContent = "";
    urlInput.className = urlInput.className.replace(" is-invalid", "");
  }

  const urlEncoded = new URLSearchParams();
  urlEncoded.append("url", url);

  //* <--------------------------------------------------- API Call --------------------------------------------------->

  const getUrl = {
    method: "POST",
    headers: {
      accept: "application/json",
      "x-apikey": apiKey,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: urlEncoded.toString(),
  };

  fetch("https://cors-anywhere.herokuapp.com/https://www.virustotal.com/api/v3/urls", getUrl)
    .then((response) => {
      if (!response.ok) {
        return response.json().then((error) => {
          throw new Error(`${response.status}: ${error.error.message}`);
        });
      }
      return response.json();
    })
    .then((data) => {
      // console.log(data);
      if (!data.data || !data.data.id) {
        throw new Error("Invalid response from URL submission");
      }

      const urlId = data.data.id;
      //* <--------------------- Rerouted for in-depth analysis to access detailed information --------------------->
      return fetch(`https://cors-anywhere.herokuapp.com/https://www.virustotal.com/api/v3/analyses/${urlId}`, {
        method: "GET",
        headers: {
          accept: "application/json",
          "x-apikey": apiKey,
        },
      });
    })
    .then((response) => {
      if (!response.ok) {
        return response.json().then((error) => {
          throw new Error(`${response.status}: ${error.error.message}`);
        });
      }
      return response.json();
    })
    .then((data) => {
      // console.log(data);
      if (!data.meta || !data.meta.url_info) {
        throw new Error("Invalid response from analysis");
      }
      const scanedUrl = data.meta.url_info.url;
      const id = data.meta.url_info.id;
      const time = data.data.attributes.date;
      const dateObject = new Date(time * 1000);
      const formattedDate = dateObject.toLocaleString();
      //* <------------------------- appends last scan date and URL-ID values to the webpage ------------------------->
      hashOutput.innerHTML = `<b>URL-ID :</b> ${id}`;
      date.innerHTML = `<b>Last Scanned :</b> ${formattedDate} <br>`;
      details.innerHTML = `<a href="https://www.virustotal.com/gui/url/${id}" target="_blank">
                            <button type="button" class="btn btn-success">View Detailed Report</button></a>
                            <p class="text-success fw-bold">Note : Recommended to View Detailed Report for more information. </p>
                            <p class="text-danger fw-bolder"> If No VirusTotal reports available for this item use Detailed Report.</p>`;

      //* <-------------------------- Rerouted to get widget report of the scanned file -------------------------->
      return fetch(
        `https://cors-anywhere.herokuapp.com/https://www.virustotal.com/api/v3/widget/url?query=${scanedUrl}`,
        {
          method: "GET",
          headers: {
            accept: "application/json",
            "x-apikey": apiKey,
          },
        }
      );
    })
    .then((response) => {
      if (!response.ok) {
        return response.json().then((error) => {
          throw new Error(`${response.status}: ${error.error.message}`);
        });
      }
      return response.json();
    })
    .then((data) => {
      // console.log(data);
      if (!data.data || !data.data.url) {
        throw new Error("Invalid response from widget request");
      }
      const url = data.data.url;

      //* <--------------------------------------- insert widget to the webpage --------------------------------------->
      widget.src = url;
      iframeContainer.className = iframeContainer.className.replace(
        "d-none",
        "d-block"
      );
      iframeContainer.appendChild(widget);
    })
    //* <----------------------------------------- Error Handling --------------------------------------------->
    .catch((error) => {
      console.log("Error : ", error.message);
      urlInfo.textContent = `Error: ${error.message}`;
      urlInput.className += " is-invalid";
      hashOutput.innerHTML = "";
    });
});
