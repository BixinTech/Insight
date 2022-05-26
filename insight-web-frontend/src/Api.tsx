import axios from "axios";

export const API_BASE_URL = "http://192.168.0.108:9080";

const Api = axios.create({
  baseURL: `${API_BASE_URL}`,
});

// Api.interceptors.request.use((config) => ({
//   ...config,
//   params: {
//     ...(config.params || {}),
//     _: + new Date()
//   }
// }))

Api.interceptors.response.use(
  (response) => {
    if (response && response.data) {
      return Promise.resolve(response.data);
    } else {
      return Promise.reject("response 404");
    }
  },
  (error) => {
    console.log("-- error --");
    console.log(error);
    console.log("-- error --");
    return Promise.reject({
      success: false,
      msg: error,
    });
  }
);

export default Api;
