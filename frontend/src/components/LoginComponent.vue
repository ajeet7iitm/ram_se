<template>
  <div class="background">
    <div class="flex-wrapper">
      <div class="container">
        <h1 class="text-center">Login</h1>
        <form @submit.prevent="loginUser">
          <div class="form-group">
            <label>Email</label>
            <input type="text" v-model="email" class="form-control" placeholder="Enter Email" autocomplete="off" required />
          </div>
          <div class="form-group">
            <label>Password</label>
            <input type="password" v-model="password" class="form-control" placeholder="Password" autocomplete="off" required />
          </div>
          <button type="submit" class="btn btn-primary btn-block">Submit</button>

          <p class="text text-center" style="margin-top:20px">
            <router-link to="/changePassword">Change Password</router-link>
          </p>
          <p class="text text-center" style="margin-top:20px">
            <router-link to="/register">Registration</router-link>
          </p>
        </form>
      </div>
    </div>
  </div>
</template>

<script>
import axios from "axios";
export default {
  name: "LoginComponent",
  data() {
    return {
      email: "",
      password: ""
    };
  },
  methods: {
    loginUser(e) {
      e.preventDefault();
      console.log(this.email, this.password);
      axios.post("/login", {
        email: this.email,
        password: this.password
      }).then(res => {
        console.log(res);
        if (res.status == 200) {
          localStorage.setItem("token", res.data.token);
          localStorage.setItem("id", res.data.id);
          this.$store.dispatch("id", res.data.id);
          localStorage.setItem("role", res.data.role);
          this.$store.dispatch("role", res.data.role);
          axios.defaults.headers.common["secret_authtoken"] = res.data.token;
          if(res.data.role == "1" || res.data.role == "2" || res.data.role == "3" || res.data.role == "4"){
            this.$router.push("/dashboard");
          }
        } else {
          alert(res.data.message);
        }
      }).catch(err => {
        console.log(err);
      });
    },
  }
}
</script>

<style scoped>
.background {
  background-image: url('../login.jpg'); /* Replace '/path/to/your/image.jpg' with the actual path to your image */
  background-size: cover;
  background-position: center;
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  display: flex;
  justify-content: center;
  align-items: center;
}

.flex-wrapper {
  max-width: 400px; /* Adjust the max-width as needed */
  width: 100%;
}

.container {
  font-family: Arial, sans-serif;
  padding: 20px;
  border-radius: 10px;
  background-color: rgba(255, 255, 255, 0.9); /* Adding some transparency to the container */
  box-shadow: 0px 0px 10px rgba(0, 0, 0, 0.1);
}

.container h1 {
  text-align: center;
  margin-bottom: 20px;
  color: #333;
}

.form-group {
  margin-bottom: 20px;
}

label {
  font-size: 18px;
  font-weight: 500;
  color: #555;
}

.btn {
  display: block;
  width: 100%;
  padding: 10px 0;
  font-size: 16px;
  font-weight: bold;
  color: #fff;
  background-color: #4CAF50;
  border: none;
  border-radius: 5px;
  cursor: pointer;
}

.btn:hover {
  background-color: #45a049;
}

.text {
  font-size: 14px;
  color: #666;
}

.text-center {
  text-align: center;
}

</style>

