<template><input :aria-label="label" v-bind="props"><img :alt="description" src="x">
<p v-if="loading">Loading</p><p v-if="error">Error</p><p v-if="!items.length">Empty</p>
<ul><li v-for="item in items">{{ item.name }}</li></ul></template>
