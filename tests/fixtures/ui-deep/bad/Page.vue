<template>
<input placeholder="Email">
<img src="photo.png">
<div @click="save">Save</div>
<ul><li v-for="item in items">{{ item.name }}</li></ul>
</template>
