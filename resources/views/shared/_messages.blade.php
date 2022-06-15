@foreach(['danger', 'warning', 'success', 'info'] as $msg)
  @if(session()->has($msg))
    <div class="flash-message">
      <p class="alert alert-{{ $msg }}">
        {{ session()->get($msg) }}
        {{ session()->flash('success', 'This is a success alert—check it out!') }}
      </p>
    </div>
  @endif
@endforeach
