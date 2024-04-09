import { createStore } from "vuex";

export default createStore({ 
    state:{
        id: parseInt(localStorage.getItem('id')),
        role: parseInt(localStorage.getItem('role')),
    },
    getters:{
        id: (state) => {
            return state.id;
          },
        role: (state) => {
            return state.role;
          },
    },
    mutations:{
        id(state, id ) { 
            state.id = id;
          },
        role(state, role ) {
            state.role = role;
          },
    },
    actions: {
        id(context, id) {
            context.commit("id", id);
          },
        role(context, role) {
            context.commit("role", role);
          },   
    },
    modules: {},
})