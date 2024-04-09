<template>
    <div class="background">
      <div class="flex-wrapper">
        <div class="container">
          <h1 class="text-center">Registration</h1>
          <form @submit.prevent="registerUser">
            <div class="form-group">
              <label>Email</label>
              <input type="text" v-model="email" class="form-control" placeholder="Enter Email" autocomplete="off" required />
            </div>
            <div class="form-group">
              <label>Password</label>
              <input type="password" v-model="password" class="form-control" placeholder="Password" autocomplete="off" required />
            </div>
            <div class="form-group">
                <label>Retype Password</label>
                <input type="password" v-model="retypePassword" class="form-control" placeholder="Retype Password" autocomplete="off" required />
            </div>
            <button type="submit" class="btn btn-primary btn-block">Submit</button>
            <p class="text text-center" style="margin-top:20px">
            <router-link to="/">Login</router-link>
          </p>
          </form>
        </div>
      </div>
    </div>
  </template>
  
  <script>
  import axios from "axios";
  export default {
    name: "RegistrationComponent",
    data() {
      return {
        email: "",
        password: "",
        retypePassword: ""
      };
    },
    methods: {
      registerUser(e) {
        e.preventDefault();
        if (this.password !== this.retypePassword) {
            alert("Passwords do not match");
            return;
        }
        console.log(this.email, this.password);
        axios.post("/api/discourse/register", {
          email: this.email,
          password: this.password
        }).then(res => {
          console.log(res);
          if (res.status == 200 && res.data.code == 200) {
            alert(res.data.message);
            //alert("Registration successful! Please check your email for verification.");
            this.$router.push("/");
          }
           else {
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
  /* Same as the styles for LoginComponent */
  .background {
    background-image: url('../login.jpg');
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
    max-width: 400px;
    width: 100%;
  }
  
  .container {
    font-family: Arial, sans-serif;
    padding: 20px;
    border-radius: 10px;
    background-color: rgba(255, 255, 255, 0.9);
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