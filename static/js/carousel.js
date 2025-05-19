document.addEventListener("DOMContentLoaded", function () {
  const slides = document.querySelectorAll(".carousel-slide");
  let current = 0;

  function showSlide(index) {
    slides.forEach((slide, i) => {
      slide.classList.toggle("active", i === index);
    });
  }

  document.getElementById("next").addEventListener("click", function () {
    current = (current + 1) % slides.length;
    showSlide(current);
  });

  document.getElementById("prev").addEventListener("click", function () {
    current = (current - 1 + slides.length) % slides.length;
    showSlide(current);
  });
});